"""Reading the application queue out of the registry.

Applications are the one collection Corliss reads from the **index** rather
than from the registry space, and the tests that matter here are the ones that
keep an applicant from disappearing quietly:

- the applicant's DID is the repo half of the record uri and nothing else — the
  index sends no `did` field, so a uri that will not parse names nobody;
- a row that cannot be read is **counted**, never dropped, because the failure
  mode this whole panel exists to prevent is somebody asking to join and the
  console not showing it;
- the read needs the registry URL and **not** the reconcile token, so a
  deployment without one still shows the queue.

Nothing here touches the network: `requests.get` is mocked at the boundary,
exactly as in `test_registry.py`.
"""

import json
from unittest.mock import patch

import requests
from django.test import TestCase

from corliss import membership

URL = "https://registry.example"
HOST = "view.registry.example"
CLIENT_KEY = "hvc_testkey"

# The four DIDs production actually had on file when this was written, so the
# fixture below is a real payload rather than an invented one.
APPLICANT = "did:plc:z7tuu4dmfvoqlm2wensjxons"
OTHER = "did:plc:hhyrsndukexwr6qucdngcf4r"

LIST_REQUESTS = membership.LIST_REQUESTS_NSID


def request_row(did=APPLICANT, created_at="2026-08-17T13:44:05.472Z", note="HEYO"):
    """One row exactly as `listRequests` hands it back: the record's fields
    flat, with the uri alongside and no `did` anywhere."""
    row = {
        "$type": "network.sharedcomputer.membership.request",
        "createdAt": created_at,
        "uri": f"at://{did}/network.sharedcomputer.membership.request/self",
    }
    if note is not None:
        row["note"] = note
    return row


class FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def registry(url=URL, client_key=CLIENT_KEY, token="reconcile-token", host=""):
    return membership.MembershipRegistry(url, client_key, token, host)


class DidFromUriTests(TestCase):
    """The subject of an application, which is not a field of it."""

    def test_the_repo_half_of_the_uri_is_the_applicant(self):
        uri = f"at://{APPLICANT}/network.sharedcomputer.membership.request/self"
        self.assertEqual(membership.did_from_uri(uri), APPLICANT)

    def test_anything_that_is_not_a_record_uri_is_refused(self):
        for bad in [
            None,
            "",
            APPLICANT,
            "https://example.com/foo",
            "at:///network.sharedcomputer.membership.request/self",
            "at://not-a-did/collection/self",
        ]:
            with self.subTest(bad):
                with self.assertRaises(membership.PushError):
                    membership.did_from_uri(bad)


class FetchApplicationsTests(TestCase):
    def test_the_production_payload_shape_parses(self):
        payload = {
            "requests": [
                request_row(),
                request_row(did=OTHER, created_at="2026-08-12T18:13:44.137Z",
                            note="Boop 2000"),
            ]
        }
        with patch.object(requests, "get", return_value=FakeResponse(payload)):
            listing = registry().fetch_applications()

        self.assertEqual([a.did for a in listing], [APPLICANT, OTHER])
        self.assertEqual(listing.applications[0].note, "HEYO")
        self.assertEqual(
            listing.applications[0].created_at.isoformat(),
            "2026-08-17T13:44:05.472000+00:00",
        )
        self.assertEqual(listing.unreadable, 0)
        self.assertFalse(listing.truncated)

    def test_an_application_with_no_note_keeps_the_applicant(self):
        payload = {"requests": [request_row(note=None)]}
        with patch.object(requests, "get", return_value=FakeResponse(payload)):
            listing = registry().fetch_applications()

        self.assertEqual(len(listing), 1)
        self.assertEqual(listing.applications[0].note, "")

    def test_an_unreadable_uri_is_counted_not_dropped(self):
        """The one field with no fallback. Silence here loses a person."""
        row = request_row()
        row["uri"] = "not-a-uri"
        payload = {"requests": [row, request_row(did=OTHER)]}

        with patch.object(requests, "get", return_value=FakeResponse(payload)):
            listing = registry().fetch_applications()

        self.assertEqual([a.did for a in listing], [OTHER])
        self.assertEqual(listing.unreadable, 1)

    def test_a_malformed_date_does_not_lose_the_applicant(self):
        """Unlike the uri, a date has a sensible fallback: none at all."""
        payload = {"requests": [request_row(created_at="last tuesday")]}
        with patch.object(requests, "get", return_value=FakeResponse(payload)):
            listing = registry().fetch_applications()

        self.assertEqual([a.did for a in listing], [APPLICANT])
        self.assertIsNone(listing.applications[0].created_at)
        self.assertEqual(listing.unreadable, 0)

    def test_the_cursor_is_followed_to_the_end(self):
        pages = [
            FakeResponse({"requests": [request_row()], "cursor": "page2"}),
            FakeResponse({"requests": [request_row(did=OTHER)]}),
        ]
        with patch.object(requests, "get", side_effect=pages) as get:
            listing = registry().fetch_applications()

        self.assertEqual([a.did for a in listing], [APPLICANT, OTHER])
        self.assertFalse(listing.truncated)
        self.assertEqual(get.call_count, 2)
        self.assertNotIn("cursor", get.call_args_list[0].kwargs["params"])
        self.assertEqual(get.call_args_list[1].kwargs["params"]["cursor"], "page2")

    def test_a_cursor_that_never_clears_stops_and_says_so(self):
        """A prefix presented as the whole queue would be the worst outcome."""
        forever = FakeResponse({"requests": [request_row()], "cursor": "more"})
        with patch.object(requests, "get", return_value=forever) as get:
            listing = registry().fetch_applications()

        self.assertEqual(get.call_count, membership.APPLICATIONS_MAX_PAGES)
        self.assertTrue(listing.truncated)

    def test_it_reads_without_the_reconcile_token(self):
        """`listRequests` takes no credential, so requiring one would hide the
        queue on a deployment that has not been given a token it cannot use."""
        with patch.object(
            requests, "get", return_value=FakeResponse({"requests": []})
        ) as get:
            listing = registry(token="").fetch_applications()

        self.assertEqual(len(listing), 0)
        self.assertNotIn("token", get.call_args.kwargs["params"])

    def test_the_reconcile_token_is_never_sent_here(self):
        """It buys nothing at this endpoint, and a token in a URL is a token in
        a log. The two doors stay separate on the wire as well as in the Lua."""
        with patch.object(
            requests, "get", return_value=FakeResponse({"requests": []})
        ) as get:
            registry(token="secret-token").fetch_applications()

        self.assertEqual(
            get.call_args.kwargs["params"], {"limit": membership.APPLICATIONS_PAGE_SIZE}
        )
        self.assertNotIn("secret-token", get.call_args.args[0])

    def test_it_calls_the_list_requests_query(self):
        with patch.object(
            requests, "get", return_value=FakeResponse({"requests": []})
        ) as get:
            registry().fetch_applications()

        self.assertEqual(get.call_args.args[0], f"{URL}/xrpc/{LIST_REQUESTS}")

    def test_the_host_override_applies_here_too(self):
        """Shared with `fetch_events` through `_query`: HappyView routes by
        virtual host, so the internal address needs the public name by hand."""
        with patch.object(
            requests, "get", return_value=FakeResponse({"requests": []})
        ) as get:
            registry(host=HOST).fetch_applications()

        self.assertEqual(get.call_args.kwargs["headers"]["Host"], HOST)

    def test_an_unconfigured_url_names_the_setting_to_fix(self):
        with self.assertRaises(membership.RegistryError) as caught:
            registry(url="").fetch_applications()

        self.assertIn("MEMBERSHIP_REGISTRY_URL", str(caught.exception))
        # And it does not demand the token reconciliation needs.
        self.assertNotIn("MEMBERSHIP_REGISTRY_TOKEN", str(caught.exception))

    def test_an_unreachable_registry_raises_rather_than_reading_as_empty(self):
        with patch.object(
            requests, "get", side_effect=requests.ConnectionError("no route")
        ):
            with self.assertRaises(membership.RegistryError) as caught:
                registry().fetch_applications()

        self.assertIn("could not reach the registry", str(caught.exception))

    def test_a_non_200_carries_the_registrys_own_words(self):
        with patch.object(
            requests, "get", return_value=FakeResponse("script_error: boom", 500)
        ):
            with self.assertRaises(membership.RegistryError) as caught:
                registry().fetch_applications()

        self.assertIn("500", str(caught.exception))
        self.assertIn("script_error: boom", str(caught.exception))

    def test_a_response_with_no_requests_array_is_refused(self):
        """Not read as "nobody has applied" — the shape is wrong, so the answer
        is unknown."""
        with patch.object(
            requests, "get", return_value=FakeResponse({"applications": []})
        ):
            with self.assertRaises(membership.RegistryError):
                registry().fetch_applications()
