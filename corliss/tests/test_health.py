"""`corliss.health` — the probes behind /systems/.

Every test here patches at the `requests` or `socket` boundary. A health check
suite that reached the network would pass or fail on whether the developer
happened to be on the cluster's bridge, which is the one thing it must never
depend on.

What is worth asserting, in order of what would actually bite:

1. An unconfigured probe says `unknown`, never `down`. Getting this backwards
   turns a blank setting into a reported outage, and the page's whole claim is
   that it does not guess.
2. No probe raises. This runs on a page render; an exception is a 500 on the
   page an admin opens *because* something is already wrong.
3. Redis's `-NOAUTH` counts as up, which is not obvious and is the reason there
   is no redis dependency in this project.
"""

import socket
from unittest.mock import MagicMock, patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings

from corliss import health


def _response(status):
    """A `requests` response stub carrying only what the probes read."""
    stub = MagicMock()
    stub.status_code = status
    return stub


class UnconfiguredTests(TestCase):
    """A blank setting is a question we cannot answer, not a failure."""

    @override_settings(
        SYNC_RELAY_URL="",
        REDIS_URL="",
        GARAGE_S3_URL="",
        CADDY_HEALTH_URL="",
        LITELLM_URL="",
        MEMBERSHIP_REGISTRY_URL="",
        OIDC_BACKCHANNEL_LOGOUT_URI="",
    )
    def test_every_unset_probe_reads_unknown_and_dials_nothing(self):
        probes = (health._sync_relay, health._redis, health._garage,
                  health._caddy, health._litellm, health._happyview,
                  health._open_webui)
        with patch("corliss.health.requests.get") as get, \
                patch("corliss.health.socket.create_connection") as connect:
            for probe in probes:
                self.assertEqual(probe(), health.UNKNOWN, probe.__name__)
        # The point is not just the answer but the absence of the attempt: an
        # empty URL handed to requests raises MissingSchema, which would read
        # as "down" through the RequestException branch.
        get.assert_not_called()
        connect.assert_not_called()

    @override_settings(GARAGE_S3_URL="not-a-url")
    def test_a_malformed_url_is_unknown_not_down(self):
        # Nobody's Garage is broken; ours is misconfigured, and the page must
        # not blame the service for that.
        with patch("corliss.health.requests.get") as get:
            self.assertEqual(health._garage(), health.UNKNOWN)
        get.assert_not_called()


@override_settings(SYNC_RELAY_URL="http://10.1.1.113:7030")
class HttpProbeTests(TestCase):
    """Transport failure and HTTP status are different failures."""

    def test_a_healthy_service_is_up(self):
        with patch("corliss.health.requests.get", return_value=_response(200)):
            self.assertEqual(health._sync_relay(), health.UP)

    def test_an_unreachable_service_is_down_and_does_not_propagate(self):
        with patch("corliss.health.requests.get",
                   side_effect=requests.ConnectionError("no route to host")):
            self.assertEqual(health._sync_relay(), health.DOWN)

    def test_a_timeout_is_down(self):
        with patch("corliss.health.requests.get", side_effect=requests.Timeout()):
            self.assertEqual(health._sync_relay(), health.DOWN)

    def test_an_error_status_is_down(self):
        with patch("corliss.health.requests.get", return_value=_response(502)):
            self.assertEqual(health._sync_relay(), health.DOWN)

    def test_the_health_path_is_appended_to_the_origin(self):
        with patch("corliss.health.requests.get", return_value=_response(200)) as get:
            health._sync_relay()
        self.assertEqual(get.call_args.args[0], "http://10.1.1.113:7030/health")

    @override_settings(SYNC_RELAY_URL="http://10.1.1.113:7030/some/path")
    def test_a_path_on_the_setting_is_discarded_not_concatenated(self):
        with patch("corliss.health.requests.get", return_value=_response(200)) as get:
            health._sync_relay()
        self.assertEqual(get.call_args.args[0], "http://10.1.1.113:7030/health")

    def test_redirects_are_never_followed(self):
        # HappyView answers / with a 302 and that IS healthy. Following it would
        # probe wherever it points and can hang the page on a chain.
        with patch("corliss.health.requests.get", return_value=_response(200)) as get:
            health._sync_relay()
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)


class GarageTests(TestCase):
    """Its admin API is loopback-only, so the S3 port is what we get."""

    @override_settings(GARAGE_S3_URL="http://10.1.1.101:3900")
    def test_a_403_from_the_s3_endpoint_is_a_serving_garage(self):
        # An unauthenticated GET on S3 answers an XML error. Treating that as
        # down would paint Garage red on a perfectly healthy cluster.
        with patch("corliss.health.requests.get", return_value=_response(403)):
            self.assertEqual(health._garage(), health.UP)

    @override_settings(GARAGE_S3_URL="http://10.1.1.101:3900")
    def test_but_nothing_answering_is_still_down(self):
        with patch("corliss.health.requests.get",
                   side_effect=requests.ConnectionError("refused")):
            self.assertEqual(health._garage(), health.DOWN)


@override_settings(
    MEMBERSHIP_REGISTRY_URL="http://10.1.1.111:3000",
    MEMBERSHIP_REGISTRY_HOST="view.example.net",
)
class HappyViewTests(TestCase):

    def test_the_public_host_header_is_presented(self):
        # Not because `/` needs it — measured 2026-08-31, HappyView answers 303
        # there with or without it, and the 421 "Unknown host" it is famous for
        # belongs to the XRPC routes. The header is asserted because a probe
        # should dial a service the way the code it vouches for does, and every
        # other call Corliss makes here carries MEMBERSHIP_REGISTRY_HOST.
        with patch("corliss.health.requests.get", return_value=_response(302)) as get:
            self.assertEqual(health._happyview(), health.UP)
        self.assertEqual(get.call_args.kwargs["headers"], {"Host": "view.example.net"})

    def test_a_302_is_healthy(self):
        with patch("corliss.health.requests.get", return_value=_response(302)):
            self.assertEqual(health._happyview(), health.UP)


@override_settings(REDIS_URL="redis://10.1.1.103:6379")
class RedisTests(TestCase):
    """No client library, and the refusal is the measurement."""

    def _ping(self, reply):
        sock = MagicMock()
        sock.recv.return_value = reply
        conn = MagicMock()
        conn.__enter__.return_value = sock
        with patch("corliss.health.socket.create_connection", return_value=conn) as connect:
            state = health._redis()
        return state, connect, sock

    def test_pong_is_up(self):
        state, _, sock = self._ping(b"+PONG\r\n")
        self.assertEqual(state, health.UP)
        sock.sendall.assert_called_once_with(b"PING\r\n")

    def test_noauth_is_also_up(self):
        # The cluster sets requirepass, so this is the ANSWER WE ACTUALLY GET.
        # Only a Redis that is up, listening and speaking its protocol can
        # refuse us this way — which is everything the page claims by "Up".
        state, _, _ = self._ping(b"-NOAUTH Authentication required.\r\n")
        self.assertEqual(state, health.UP)

    def test_something_that_is_not_redis_is_down(self):
        state, _, _ = self._ping(b"HTTP/1.1 400 Bad Request\r\n")
        self.assertEqual(state, health.DOWN)

    def test_a_refused_connection_is_down(self):
        with patch("corliss.health.socket.create_connection",
                   side_effect=ConnectionRefusedError()):
            self.assertEqual(health._redis(), health.DOWN)

    def test_a_dns_failure_is_down_not_an_exception(self):
        with patch("corliss.health.socket.create_connection",
                   side_effect=socket.gaierror("name resolution failed")):
            self.assertEqual(health._redis(), health.DOWN)

    def test_the_port_comes_from_the_url(self):
        _, connect, _ = self._ping(b"+PONG\r\n")
        self.assertEqual(connect.call_args.args[0], ("10.1.1.103", 6379))

    @override_settings(REDIS_URL="redis://10.1.1.103")
    def test_and_defaults_to_6379_when_the_url_omits_it(self):
        _, connect, _ = self._ping(b"+PONG\r\n")
        self.assertEqual(connect.call_args.args[0], ("10.1.1.103", 6379))


class PostgresTests(TestCase):

    def test_a_live_connection_is_up(self):
        self.assertEqual(health._postgres(), health.UP)

    def test_a_database_error_is_down_rather_than_a_500(self):
        from django.db import OperationalError
        with patch("corliss.health.connection.cursor",
                   side_effect=OperationalError("server closed the connection")):
            self.assertEqual(health._postgres(), health.DOWN)


class BrokenProbeTests(TestCase):
    """Our bug is not their outage."""

    def test_a_probe_that_raises_reads_unknown_not_down(self):
        probe = health.Probe("Anything", "…", MagicMock(side_effect=RuntimeError("boom")))
        with self.assertLogs("corliss.health", level="ERROR"):
            self.assertEqual(health._safely(probe), health.UNKNOWN)


@override_settings(
    SYNC_RELAY_URL="http://10.1.1.113:7030",
    REDIS_URL="redis://10.1.1.103:6379",
    GARAGE_S3_URL="http://10.1.1.101:3900",
    CADDY_HEALTH_URL="http://10.1.1.110/healthz",
    LITELLM_URL="http://10.1.1.112:4000",
    MEMBERSHIP_REGISTRY_URL="http://10.1.1.111:3000",
    MEMBERSHIP_REGISTRY_HOST="view.example.net",
    OIDC_BACKCHANNEL_LOGOUT_URI="http://10.1.1.121:8080/oauth/backchannel-logout",
)
class CheckAllTests(TestCase):
    """The whole stack, cached. A fully configured deployment, so that the
    states these assert on are the probes' answers and not a blank setting's."""

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_it_returns_every_service_in_the_stack(self):
        with patch("corliss.health._measure", wraps=health._measure), \
                patch("corliss.health.requests.get", return_value=_response(200)), \
                patch("corliss.health.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value.recv.return_value = b"+PONG\r\n"
            groups = health.check_all()

        named = {s["name"] for g in groups for s in g["services"]}
        self.assertEqual(named, {p.name for _, ps in health.STACK for p in ps})
        self.assertEqual([g["name"] for g in groups], ["Core", "Platform", "Applications"])

    def test_every_service_carries_a_label_matching_its_state(self):
        with patch("corliss.health.requests.get", return_value=_response(200)), \
                patch("corliss.health.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value.recv.return_value = b"+PONG\r\n"
            groups = health.check_all()

        for group in groups:
            for service in group["services"]:
                self.assertEqual(service["label"], health._LABELS[service["state"]])

    def test_a_second_call_inside_the_ttl_issues_no_traffic(self):
        # The reason the cache exists: without it a dead service costs the full
        # timeout on every single render of this page.
        with patch("corliss.health.requests.get", return_value=_response(200)), \
                patch("corliss.health.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value.recv.return_value = b"+PONG\r\n"
            health.check_all()

        with patch("corliss.health.requests.get") as get, \
                patch("corliss.health.socket.create_connection") as connect:
            health.check_all()
        get.assert_not_called()
        connect.assert_not_called()

    def test_refresh_asks_again(self):
        with patch("corliss.health.requests.get", return_value=_response(200)), \
                patch("corliss.health.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value.recv.return_value = b"+PONG\r\n"
            health.check_all()

        with patch("corliss.health.requests.get", return_value=_response(200)) as get, \
                patch("corliss.health.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value.recv.return_value = b"+PONG\r\n"
            health.check_all(refresh=True)
        self.assertTrue(get.called)

    def test_an_all_clear_is_held_longer_than_a_degraded_result(self):
        # A stale green dot costs nothing; a stale red one is the exact thing
        # somebody reloading this page is trying to see change.
        with patch("corliss.health.cache.set") as cache_set, \
                patch("corliss.health.requests.get", return_value=_response(200)), \
                patch("corliss.health.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value.recv.return_value = b"+PONG\r\n"
            health.check_all()
        self.assertEqual(cache_set.call_args.args[2], health.HEALTH_CACHE_TTL)

        with patch("corliss.health.cache.set") as cache_set, \
                patch("corliss.health.requests.get",
                      side_effect=requests.ConnectionError("refused")), \
                patch("corliss.health.socket.create_connection",
                      side_effect=ConnectionRefusedError()):
            health.check_all(refresh=True)
        self.assertEqual(cache_set.call_args.args[2], health.HEALTH_DEGRADED_TTL)

    def test_every_row_in_the_stack_is_something_that_can_be_asked(self):
        # The list carried a "Manage Console" row describing static files that
        # had already been deleted with the manage_console role. A page whose
        # claim is that it does not guess must not list what is not there, and
        # a row nobody can probe would also pin the cache to the degraded TTL
        # forever, so the all-clear window would never once be used.
        with patch("corliss.health.requests.get", return_value=_response(200)), \
                patch("corliss.health.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value.recv.return_value = b"+PONG\r\n"
            groups = health.check_all()

        states = [s["state"] for g in groups for s in g["services"]]
        self.assertTrue(states)
        self.assertNotIn(health.UNKNOWN, states)

    def test_one_dead_service_does_not_take_the_others_with_it(self):
        with patch("corliss.health.requests.get",
                   side_effect=requests.ConnectionError("refused")), \
                patch("corliss.health.socket.create_connection",
                      side_effect=ConnectionRefusedError()):
            groups = health.check_all()

        states = {s["name"]: s["state"] for g in groups for s in g["services"]}
        self.assertEqual(states["Corliss"], health.UP)
        self.assertEqual(states["PostgreSQL"], health.UP)
        self.assertEqual(states["Sync relay"], health.DOWN)
