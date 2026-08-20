"""`corliss.litellm` — provisioning members into LiteLLM and issuing keys.

The load-bearing tests are the two that guard the provisioner key. It can mint
and delete keys for *anyone*, so the only thing standing between a member and
someone else's keys is that this module re-establishes on the server who is
asking: issuance proves membership (in the view) and the cap, revocation proves
ownership. Both are tested here against a client that answers whatever it is
told to, because a LiteLLM that returns the wrong thing is exactly the case
those checks exist for.

The third is `team_id_for` failing closed. An unscoped key is *more* permissive
than a wrongly-scoped one, so a missing team must refuse rather than fall back.

Nothing here touches the network: `requests.request` is mocked at the boundary.
"""

import json
from io import StringIO
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from corliss import litellm
from corliss.models import MembershipCache

URL = "http://10.1.1.112:4000"
TOKEN = "sk-provisioner"

MEMBER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
OTHER = "did:plc:2cxgdrgtsmrbqnjkwyplmp43"

LITELLM_SETTINGS = {
    "LITELLM_URL": URL,
    "LITELLM_PROVISIONER_KEY": TOKEN,
    "LITELLM_MAX_KEYS_PER_MEMBER": 5,
}


class FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode()

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def key_row(did=MEMBER, token="abc123def456", alias="jacob/laptop",
            created="2026-08-01", team_id="t-two"):
    """One entry as `/key/list?return_full_object=true` returns it."""
    return {
        "token": token,
        "key_name": "sk-...4f2a",
        "key_alias": alias,
        "user_id": did,
        "spend": 0.5,
        "created_at": created,
        "team_id": team_id,
        "blocked": False,
    }


class Router:
    """Answers calls by `(method, path)`, and records what it was asked.

    A dict of canned responses rather than a queue: these methods make several
    calls in an order that is an implementation detail, and a queue would make
    every test assert that order whether it cared about it or not.
    """

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, **kwargs):
        path = url[len(URL):]
        self.calls.append((method, path, kwargs.get("json"), kwargs.get("params")))
        try:
            answer = self.routes[(method, path)]
        except KeyError:  # pragma: no cover - a test asked for the unexpected
            raise AssertionError(f"unrouted call: {method} {path}")
        if callable(answer):
            answer = answer(len([c for c in self.calls if c[1] == path]))
        return answer

    def bodies(self, method, path):
        return [c[2] for c in self.calls if c[0] == method and c[1] == path]


def client():
    return litellm.LiteLLM(URL, TOKEN, max_keys=5)


class ConfigurationTests(TestCase):
    def test_unconfigured_is_inert_not_a_traceback(self):
        # A deployment that has not been given LiteLLM must say so, not 500.
        for url, token in ((URL, ""), ("", TOKEN), ("", "")):
            with self.subTest(url=url, token=token):
                bare = litellm.LiteLLM(url, token)
                self.assertFalse(bare.is_configured)
                with self.assertRaises(litellm.LiteLLMError) as caught:
                    bare.keys_for(MEMBER)
                self.assertIn("not configured", str(caught.exception))

    @override_settings(**LITELLM_SETTINGS)
    def test_from_settings_reads_the_cap(self):
        self.assertEqual(litellm.LiteLLM.from_settings().max_keys, 5)

    def test_unreachable_never_leaks_the_internal_address(self):
        # This text is rendered to a member on /api/. It must not carry the
        # URL, which is the internal address the provisioner key lives behind.
        with patch("corliss.litellm.requests.request",
                   side_effect=requests.ConnectionError("boom")):
            with self.assertRaises(litellm.LiteLLMError) as caught:
                client().keys_for(MEMBER)
        self.assertNotIn("10.1.1", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))


class TeamTests(TestCase):
    def setUp(self):
        cache.clear()

    def _router(self, teams):
        return Router({("GET", "/team/list"): FakeResponse(
            {"teams": [{"team_alias": a, "team_id": i} for a, i in teams.items()]}
        )})

    def test_tier_resolves_to_the_team_with_that_alias(self):
        router = self._router({"level-1": "t-one", "level-2": "t-two"})
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().team_id_for("level-2"), "t-two")

    def test_a_missing_team_refuses_rather_than_issuing_unscoped(self):
        # The whole reason this fails closed: a key with no team_id inherits
        # whatever the user can reach, which on a proxy with no per-user model
        # list is every model. Falling back would silently upgrade the member.
        router = self._router({"level-1": "t-one"})
        with patch("corliss.litellm.requests.request", router):
            with self.assertRaises(litellm.LiteLLMError) as caught:
                client().team_id_for("level-9")
        self.assertIn("level-9", str(caught.exception))

    def test_a_blank_tier_is_not_a_missing_team(self):
        # Grants predating the tier field exist in the production space. They
        # get no team, which is not the same as being refused a lookup.
        router = self._router({"level-1": "t-one"})
        with patch("corliss.litellm.requests.request", router):
            self.assertIsNone(client().team_id_for(""))

    def test_a_freshly_created_team_is_not_invisible_for_the_whole_ttl(self):
        answers = [
            FakeResponse({"teams": []}),
            FakeResponse({"teams": [{"team_alias": "level-3", "team_id": "t-new"}]}),
        ]
        router = Router({("GET", "/team/list"): lambda n: answers[min(n - 1, 1)]})
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().team_id_for("level-3"), "t-new")


def model_row(name, mode="chat", context=131072, api_base="http://10.1.1.113:8080/v1"):
    """One entry as `/model/info` returns it — `litellm_params` and all.

    The `api_base` is here on purpose rather than trimmed out of the fixture:
    the point of several tests below is that it does *not* come out the other
    end, and a fixture that never carried it could not show that.

    `mode=None` drops `model_info` entirely, which is what the proxy actually
    returns for a model nobody annotated — see `CLUSTER_MODELS`.
    """
    row = {
        "model_name": name,
        "litellm_params": {
            "model": f"openai/{name}",
            "api_base": api_base,
            "api_key": "sk-upstream-secret",
        },
        "model_info": {},
    }
    if mode is not None:
        row["model_info"] = {"mode": mode, "max_input_tokens": context}
    return row


# The five models on the cluster, as `/model/info` really answered on
# 2026-08-20. Kept verbatim rather than tidied because every simplification in
# the invented fixtures this replaced hid a defect: an unannotated model, a
# third mode that is neither chat nor embedding, and a context length that is
# null everywhere. A test that cannot see those is a test that passes while the
# page is wrong.
CLUSTER_MODELS = [
    model_row("nomic-embed-text", mode="embedding", context=None),
    model_row("GX10/northmini", mode=None),
    model_row("GX10/gemma-26b", mode=None),
    model_row("GTX1080/Qwen3.5-4B-notemp", mode="chat", context=None),
    model_row("GTX1080/parakeet-v2", mode="audio_transcription", context=None),
]


class ModelTests(TestCase):
    """The catalogue, and the tier it is narrowed to."""

    def setUp(self):
        cache.clear()

    def _router(self, models, teams=(("level-2", "t-two", []),)):
        return Router({
            ("GET", "/model/info"): FakeResponse({"data": models}),
            ("GET", "/team/list"): FakeResponse({"teams": [
                {"team_alias": a, "team_id": i, "models": m} for a, i, m in teams
            ]}),
        })

    def test_an_unscoped_tier_reaches_every_model(self):
        # `models: []` is LiteLLM's own spelling of "everything", and it is what
        # every tier carries today.
        router = self._router([model_row("qwen3-coder"), model_row("llama-3.3")])
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-2")
        self.assertEqual([m.name for m in found], ["llama-3.3", "qwen3-coder"])

    def test_a_narrowed_tier_gets_only_what_its_team_lists(self):
        # The shape this exists for. Nothing narrows a tier yet; when Phase F
        # does, the page must not advertise a model the key is refused for.
        router = self._router(
            [model_row("qwen3-coder"), model_row("llama-3.3")],
            teams=(("level-0", "t-zero", ["llama-3.3"]),),
        )
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-0")
        self.assertEqual([m.name for m in found], ["llama-3.3"])

    def test_a_wildcard_team_list_means_everything(self):
        for wildcard in ("*", "all-proxy-models", "all-team-models"):
            with self.subTest(wildcard=wildcard):
                cache.clear()
                router = self._router(
                    [model_row("qwen3-coder"), model_row("llama-3.3")],
                    teams=(("level-2", "t-two", [wildcard]),),
                )
                with patch("corliss.litellm.requests.request", router):
                    found = client().models("level-2")
                self.assertEqual(len(found), 2)

    def test_a_tier_with_no_team_gets_nothing_rather_than_everything(self):
        # Fails closed, the same direction `team_id_for` does. Such a member
        # cannot be issued a key at all, so listing models would advertise
        # access that does not exist.
        router = self._router([model_row("qwen3-coder")])
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().models("level-9"), [])

    def test_a_blank_tier_reaches_no_models_and_no_network(self):
        router = Router({})
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().models(""), [])
        self.assertEqual(router.calls, [])

    def test_one_model_on_two_backends_is_one_row(self):
        # `/model/info` returns an entry per deployment. A member addresses the
        # model by name either way and does not care how many serve it.
        router = self._router([
            model_row("qwen3-coder", api_base="http://10.1.1.113:8080/v1"),
            model_row("qwen3-coder", api_base="http://10.1.1.114:8080/v1"),
        ])
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-2")
        self.assertEqual([m.name for m in found], ["qwen3-coder"])

    def test_the_upstream_address_and_key_never_leave_this_module(self):
        # `litellm_params` carries the internal address of an inference node and
        # an external provider's own key. A Model is built field by field so
        # there is nothing for a template to reach.
        router = self._router([model_row("qwen3-coder")])
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-2")
        rendered = repr([(m.name, m.mode, m.context) for m in found])
        self.assertNotIn("10.1.1.113", rendered)
        self.assertNotIn("sk-upstream-secret", rendered)
        self.assertFalse(hasattr(found[0], "litellm_params"))

    def test_chat_models_sort_before_the_embedder(self):
        # The embedder is infrastructure that happens to be visible; someone
        # reading this page came looking for something to send messages to.
        router = self._router([
            model_row("nomic-embed-text", mode="embedding"),
            model_row("qwen3-coder"),
        ])
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-2")
        self.assertEqual([m.name for m in found], ["qwen3-coder", "nomic-embed-text"])

    def test_a_model_declaring_no_mode_is_treated_as_chat(self):
        # Both GX10 models on the cluster carry an empty `model_info`, and both
        # are things to talk to.
        router = self._router([{"model_name": "mystery"}])
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-2")
        self.assertTrue(found[0].is_chat)
        self.assertEqual(found[0].type_label, "chat")
        self.assertEqual(found[0].context_label, "")

    # --- against what the proxy actually returns ---------------------------

    def test_a_transcription_model_is_not_offered_as_something_to_chat_with(self):
        # `GTX1080/parakeet-v2` is ASR. Classed as chat it would head the sorted
        # list and become the quickstart's example model, and every member
        # pasting that block would get a 400 from a model that cannot chat.
        router = self._router(CLUSTER_MODELS)
        with patch("corliss.litellm.requests.request", router):
            found = {m.name: m for m in client().models("level-2")}
        parakeet = found["GTX1080/parakeet-v2"]
        self.assertFalse(parakeet.is_chat)
        self.assertEqual(parakeet.type_label, "audio transcription")

    def test_the_cluster_catalogue_sorts_chat_first_then_the_rest(self):
        router = self._router(CLUSTER_MODELS)
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-2")
        self.assertEqual([m.name for m in found], [
            "GTX1080/Qwen3.5-4B-notemp",
            "GX10/gemma-26b",
            "GX10/northmini",
            "GTX1080/parakeet-v2",
            "nomic-embed-text",
        ])

    def test_nothing_on_the_cluster_declares_a_context_length(self):
        # The state that makes /api/ drop the Context column. Not an assertion
        # that it should stay that way — it is here so that when an operator
        # sets `max_input_tokens`, this test fails and says the column is back.
        router = self._router(CLUSTER_MODELS)
        with patch("corliss.litellm.requests.request", router):
            found = client().models("level-2")
        self.assertEqual([m.context_label for m in found], [""] * 5)

    def test_an_unreadable_catalogue_raises_rather_than_reporting_none(self):
        # "No models" and "could not ask" are different facts and the view
        # renders them differently.
        router = Router({
            ("GET", "/team/list"): FakeResponse(
                {"teams": [{"team_alias": "level-2", "team_id": "t-two", "models": []}]}
            ),
            ("GET", "/model/info"): FakeResponse("nonsense", status_code=500),
        })
        with patch("corliss.litellm.requests.request", router):
            with self.assertRaises(litellm.LiteLLMError):
                client().models("level-2")

    def test_the_catalogue_is_asked_for_once_across_two_calls(self):
        router = self._router([model_row("qwen3-coder")])
        with patch("corliss.litellm.requests.request", router):
            instance = client()
            instance.models("level-2")
            instance.models("level-2")
        info = [c for c in router.calls if c[1] == "/model/info"]
        self.assertEqual(len(info), 1)

    def test_context_is_rounded_to_something_a_column_can_be_compared_in(self):
        cases = {0: "", 8192: "8k", 131072: "131k", 262144: "262k", 2000000: "2M"}
        for context, expected in cases.items():
            with self.subTest(context=context):
                model = litellm.Model(name="m", context=context)
                self.assertEqual(model.context_label, expected)


class TeamIndexTests(TestCase):
    """`teams()` still answers `{alias: id}` now it is derived, not fetched."""

    def setUp(self):
        cache.clear()

    def test_the_alias_map_survives_carrying_the_model_lists(self):
        router = Router({("GET", "/team/list"): FakeResponse({"teams": [
            {"team_alias": "level-1", "team_id": "t-one", "models": ["llama-3.3"]},
            {"team_alias": "level-2", "team_id": "t-two", "models": []},
        ]})})
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(
                client().teams(), {"level-1": "t-one", "level-2": "t-two"}
            )

    def test_a_team_with_no_models_field_is_not_a_crash(self):
        # LiteLLM has answered without it. An absent list and an empty one mean
        # the same thing here, so neither may raise.
        router = Router({("GET", "/team/list"): FakeResponse(
            {"teams": [{"team_alias": "level-2", "team_id": "t-two"}]}
        )})
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().team_id_for("level-2"), "t-two")

    def test_both_shapes_come_from_a_single_fetch(self):
        router = Router({("GET", "/team/list"): FakeResponse({"teams": [
            {"team_alias": "level-2", "team_id": "t-two", "models": []},
        ]})})
        with patch("corliss.litellm.requests.request", router):
            instance = client()
            instance.teams()
            instance.team_id_for("level-2")
        self.assertEqual(len(router.calls), 1)


class KeyListingTests(TestCase):
    def test_another_members_key_is_filtered_out_of_the_response(self):
        # Belt and braces over the user_id query parameter. If a LiteLLM
        # version ever ignores that filter, this is what stops one member
        # being handed another's key list — the worst failure available here.
        router = Router({("GET", "/key/list"): FakeResponse(
            {"keys": [key_row(MEMBER), key_row(OTHER, token="deadbeef00")]}
        )})
        with patch("corliss.litellm.requests.request", router):
            keys = client().keys_for(MEMBER)
        self.assertEqual([k.token for k in keys], ["abc123def456"])

    def test_the_user_id_filter_is_also_sent_as_a_parameter(self):
        router = Router({("GET", "/key/list"): FakeResponse({"keys": []})})
        with patch("corliss.litellm.requests.request", router):
            client().keys_for(MEMBER)
        self.assertEqual(router.calls[0][3]["user_id"], MEMBER)

    def test_the_label_is_the_members_half_of_the_alias(self):
        router = Router({("GET", "/key/list"): FakeResponse(
            {"keys": [key_row(alias="jacob.example.com/laptop")]}
        )})
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().keys_for(MEMBER)[0].label, "laptop")

    def test_an_alias_with_no_separator_still_renders(self):
        row = litellm.ApiKey(token="t", masked="", alias="legacy", spend=0,
                             created_at="", blocked=False)
        self.assertEqual(row.label, "legacy")
        blank = litellm.ApiKey(token="t", masked="", alias="", spend=0,
                               created_at="", blocked=False)
        self.assertEqual(blank.label, "(unnamed)")


class IssueKeyTests(TestCase):
    def setUp(self):
        cache.clear()

    def _routes(self, held=(), teams=(("level-2", "t-two"),)):
        return {
            ("GET", "/key/list"): FakeResponse({"keys": list(held)}),
            ("GET", "/team/list"): FakeResponse(
                {"teams": [{"team_alias": a, "team_id": i} for a, i in teams]}
            ),
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": []}}),
            ("POST", "/user/new"): FakeResponse({"user_id": MEMBER}),
            ("POST", "/team/member_add"): FakeResponse({}),
            ("POST", "/key/generate"): FakeResponse({"key": "sk-brand-new"}),
        }

    def test_the_secret_comes_back_once_and_the_key_is_scoped_to_the_tier(self):
        router = Router(self._routes())
        with patch("corliss.litellm.requests.request", router):
            secret = client().issue_key(
                MEMBER, "laptop", handle="jacob.example.com", tier="level-2"
            )
        self.assertEqual(secret, "sk-brand-new")
        body = router.bodies("POST", "/key/generate")[0]
        self.assertEqual(body["user_id"], MEMBER)
        self.assertEqual(body["key_alias"], "jacob.example.com/laptop")
        self.assertEqual(body["team_id"], "t-two")

    def test_the_alias_falls_back_to_the_did_when_the_handle_is_unknown(self):
        router = Router(self._routes())
        with patch("corliss.litellm.requests.request", router):
            client().issue_key(MEMBER, "laptop", tier="level-2")
        self.assertEqual(
            router.bodies("POST", "/key/generate")[0]["key_alias"],
            f"{MEMBER}/laptop",
        )

    def test_the_cap_refuses_before_anything_is_minted(self):
        held = [key_row(token=f"tok{n}0000000") for n in range(5)]
        router = Router(self._routes(held=held))
        with patch("corliss.litellm.requests.request", router):
            with self.assertRaises(litellm.LiteLLMError) as caught:
                client().issue_key(MEMBER, "laptop", tier="level-2")
        self.assertIn("limit", str(caught.exception))
        self.assertEqual(router.bodies("POST", "/key/generate"), [])

    def test_a_bad_label_is_refused_without_reaching_litellm(self):
        router = Router(self._routes())
        for label in ("", "   ", "-leading", "sla/sh", "x" * 65, "tab\there"):
            with self.subTest(label=label):
                with patch("corliss.litellm.requests.request", router):
                    with self.assertRaises(litellm.LiteLLMError):
                        client().issue_key(MEMBER, label, tier="level-2")
        self.assertEqual(router.calls, [])

    def test_an_existing_litellm_user_is_not_an_error(self):
        # /user/new answers 400 when the user is already there. Provisioning
        # has to be re-runnable — it is called from a push, a page load and a
        # sync command, none of which coordinate.
        routes = self._routes()
        routes[("POST", "/user/new")] = FakeResponse(
            {"error": "User already exists in db"}, status_code=400
        )
        router = Router(routes)
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(
                client().issue_key(MEMBER, "laptop", tier="level-2"),
                "sk-brand-new",
            )

    def test_a_litellm_that_returns_no_key_is_an_error_not_an_empty_secret(self):
        routes = self._routes()
        routes[("POST", "/key/generate")] = FakeResponse({"ok": True})
        with patch("corliss.litellm.requests.request", Router(routes)):
            with self.assertRaises(litellm.LiteLLMError):
                client().issue_key(MEMBER, "laptop", tier="level-2")

    def test_a_tierless_membership_cannot_mint_a_key(self):
        # A key with no team inherits every model, so a tierless grant (five
        # of them are live in the production space) and a roster admin who
        # passed GATE without a grant must both be refused here — not handed
        # an unscoped key that is *more* permissive than any tier.
        router = Router(self._routes())
        with patch("corliss.litellm.requests.request", router):
            with self.assertRaises(litellm.LiteLLMError) as caught:
                client().issue_key(MEMBER, "laptop", tier="")
        self.assertIn("no tier", str(caught.exception))
        self.assertEqual(router.calls, [])

    def test_a_missing_tier_team_stops_issuance(self):
        router = Router(self._routes(teams=(("level-1", "t-one"),)))
        with patch("corliss.litellm.requests.request", router):
            with self.assertRaises(litellm.LiteLLMError):
                client().issue_key(MEMBER, "laptop", tier="level-2")
        self.assertEqual(router.bodies("POST", "/key/generate"), [])


class RevokeKeyTests(TestCase):
    def _routes(self, held):
        return {
            ("GET", "/key/list"): FakeResponse({"keys": list(held)}),
            ("POST", "/key/delete"): FakeResponse({"deleted_keys": 1}),
        }

    def test_a_key_the_caller_owns_is_deleted(self):
        router = Router(self._routes([key_row(token="abc123def456")]))
        with patch("corliss.litellm.requests.request", router):
            client().revoke_key(MEMBER, "abc123def456")
        self.assertEqual(
            router.bodies("POST", "/key/delete"), [{"keys": ["abc123def456"]}]
        )

    def test_someone_elses_key_is_refused_and_never_deleted(self):
        # The provisioner key would happily delete it. The token arrives in a
        # form post, so this check is the only thing that makes that safe.
        router = Router(self._routes([key_row(MEMBER, token="mineaaaa1111")]))
        with patch("corliss.litellm.requests.request", router):
            with self.assertRaises(litellm.LiteLLMError) as caught:
                client().revoke_key(MEMBER, "theirsbbbb222")
        self.assertIn("not yours", str(caught.exception))
        self.assertEqual(router.bodies("POST", "/key/delete"), [])

    def test_a_malformed_token_never_reaches_litellm(self):
        router = Router(self._routes([]))
        for token in ("", "  ", "has-dashes", "sk-secret!"):
            with self.subTest(token=token):
                with patch("corliss.litellm.requests.request", router):
                    with self.assertRaises(litellm.LiteLLMError):
                        client().revoke_key(MEMBER, token)
        self.assertEqual(router.calls, [])

    def test_delete_keys_for_removes_every_key_in_one_call(self):
        held = [key_row(token="aaa11122233"), key_row(token="bbb44455566")]
        router = Router(self._routes(held))
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().delete_keys_for(MEMBER), 2)
        self.assertEqual(
            router.bodies("POST", "/key/delete"),
            [{"keys": ["aaa11122233", "bbb44455566"]}],
        )

    def test_deleting_keys_for_a_member_with_none_calls_nothing(self):
        router = Router(self._routes([]))
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().delete_keys_for(MEMBER), 0)
        self.assertEqual(router.bodies("POST", "/key/delete"), [])


class TeamMembershipTests(TestCase):
    def test_set_team_moves_the_member_off_every_other_team(self):
        router = Router({
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": ["t-old"]}}),
            ("POST", "/team/member_delete"): FakeResponse({}),
            ("POST", "/team/member_add"): FakeResponse({}),
        })
        with patch("corliss.litellm.requests.request", router):
            client().set_team(MEMBER, "t-new")
        self.assertEqual(
            router.bodies("POST", "/team/member_delete"),
            [{"team_id": "t-old", "user_id": MEMBER}],
        )
        self.assertEqual(
            router.bodies("POST", "/team/member_add"),
            [{"team_id": "t-new", "member": {"user_id": MEMBER, "role": "user"}}],
        )

    def test_set_team_none_leaves_the_member_in_no_team(self):
        router = Router({
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": ["t-old"]}}),
            ("POST", "/team/member_delete"): FakeResponse({}),
        })
        with patch("corliss.litellm.requests.request", router):
            client().set_team(MEMBER, None)
        self.assertEqual(len(router.bodies("POST", "/team/member_delete")), 1)

    def test_an_unchanged_team_is_not_re_added(self):
        router = Router({
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": ["t-two"]}}),
        })
        with patch("corliss.litellm.requests.request", router):
            client().set_team(MEMBER, "t-two")
        self.assertEqual(router.bodies("POST", "/team/member_add"), [])

    def test_already_a_member_is_tolerated(self):
        router = Router({
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": []}}),
            ("POST", "/team/member_add"): FakeResponse(
                {"error": "User already in team"}, status_code=400
            ),
        })
        with patch("corliss.litellm.requests.request", router):
            client().set_team(MEMBER, "t-two")  # must not raise

    def test_not_a_member_is_tolerated_on_removal(self):
        router = Router({
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": ["t-old"]}}),
            ("POST", "/team/member_delete"): FakeResponse(
                {"error": "Team member not found"}, status_code=400
            ),
        })
        with patch("corliss.litellm.requests.request", router):
            client().set_team(MEMBER, None)  # must not raise


class PruneForeignKeysTests(TestCase):
    """What a tier change costs, now that LiteLLM will not re-team a key.

    `/key/update` with a new `team_id` answers 403 and the key does not move
    (probed against the deployed proxy, 2026-08-19). A key's access comes from
    the team it was minted against, so the only way a tier change can take
    effect is to delete the keys that predate it.
    """

    def _router(self, held):
        return Router({
            ("GET", "/key/list"): FakeResponse({"keys": list(held)}),
            ("POST", "/key/delete"): FakeResponse({}),
        })

    def test_keys_on_another_team_are_deleted(self):
        held = [key_row(token="aaa11122233", team_id="t-old"),
                key_row(token="bbb44455566", team_id="t-old")]
        router = self._router(held)
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().prune_foreign_keys(MEMBER, "t-new"), 2)
        self.assertEqual(
            router.bodies("POST", "/key/delete"),
            [{"keys": ["aaa11122233", "bbb44455566"]}],
        )

    def test_keys_already_on_the_right_team_are_left_alone(self):
        # This is what keeps a reconcile replay on a rebuilt cluster quiet: it
        # re-applies every grant, and every key is already where it belongs.
        router = self._router([key_row(team_id="t-new")])
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().prune_foreign_keys(MEMBER, "t-new"), 0)
        self.assertEqual(router.bodies("POST", "/key/delete"), [])

    def test_only_the_stale_ones_go(self):
        held = [key_row(token="staleaaa1111", team_id="t-old"),
                key_row(token="currentbb222", team_id="t-new")]
        router = self._router(held)
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().prune_foreign_keys(MEMBER, "t-new"), 1)
        self.assertEqual(
            router.bodies("POST", "/key/delete"), [{"keys": ["staleaaa1111"]}]
        )

    def test_a_move_to_no_team_takes_every_key(self):
        # Downgraded to a tierless grant: no team means no entitlement, so the
        # keys that carried one go with it.
        router = self._router([key_row(team_id="t-old")])
        with patch("corliss.litellm.requests.request", router):
            self.assertEqual(client().prune_foreign_keys(MEMBER, None), 1)


class UsageTests(TestCase):
    ACTIVITY = {
        "results": [
            {
                "date": "2026-08-18",
                "breakdown": {"model_groups": {"claude-opus": {"metrics": {
                    "prompt_tokens": 10, "completion_tokens": 5,
                    "total_tokens": 15, "spend": 0.01, "api_requests": 2,
                }}}},
                "metrics": {"api_requests": 2},
            },
            {
                "date": "2026-08-17",
                "breakdown": {"models": {}},
                "metrics": {"api_requests": 3, "total_tokens": 0},
            },
            {
                "date": "2026-08-16",
                "breakdown": {"models": {}},
                "metrics": {"api_requests": 0},
            },
        ],
        "metadata": {
            "total_prompt_tokens": 10, "total_completion_tokens": 5,
            "total_tokens": 15, "total_spend": 0.01, "total_api_requests": 5,
        },
    }

    def test_the_model_name_is_the_one_a_member_asked_for(self):
        # LiteLLM breaks usage down twice: `model_groups` by the name the
        # caller requested, `models` by the upstream route it resolved to
        # ("openai/nomic-embed-text"). A member's table names what they typed.
        activity = {
            "results": [{
                "date": "2026-08-18",
                "breakdown": {
                    "model_groups": {"nomic-embed-text": {"metrics": {"api_requests": 3}}},
                    "models": {"openai/nomic-embed-text": {"metrics": {"api_requests": 3}}},
                },
                "metrics": {"api_requests": 3},
            }],
            "metadata": {},
        }
        router = Router({("GET", "/user/daily/activity"): FakeResponse(activity)})
        with patch("corliss.litellm.requests.request", router):
            rows, _ = client().usage(MEMBER, "2026-08-01", "2026-08-19")
        self.assertEqual([r["model"] for r in rows], ["nomic-embed-text"])

    def test_rows_are_flattened_per_day_and_model_with_totals(self):
        router = Router({("GET", "/user/daily/activity"): FakeResponse(self.ACTIVITY)})
        with patch("corliss.litellm.requests.request", router):
            rows, totals = client().usage(MEMBER, "2026-08-01", "2026-08-19")
        self.assertEqual(rows[0]["date"], "2026-08-18")
        self.assertEqual(rows[0]["model"], "claude-opus")
        self.assertEqual(rows[0]["total_tokens"], 15)
        self.assertEqual(totals["requests"], 5)

    def test_a_day_that_reached_no_model_still_gets_a_row(self):
        # Failures, mostly. Dropping them would make usage silently incomplete
        # on exactly the days a member is most likely to be looking.
        router = Router({("GET", "/user/daily/activity"): FakeResponse(self.ACTIVITY)})
        with patch("corliss.litellm.requests.request", router):
            rows, _ = client().usage(MEMBER, "2026-08-01", "2026-08-19")
        modelless = [r for r in rows if r["date"] == "2026-08-17"]
        self.assertEqual(len(modelless), 1)
        self.assertEqual(modelless[0]["requests"], 3)

    def test_a_day_with_no_requests_at_all_gets_no_row(self):
        router = Router({("GET", "/user/daily/activity"): FakeResponse(self.ACTIVITY)})
        with patch("corliss.litellm.requests.request", router):
            rows, _ = client().usage(MEMBER, "2026-08-01", "2026-08-19")
        self.assertEqual([r for r in rows if r["date"] == "2026-08-16"], [])

    def test_a_blank_did_is_refused_before_the_call(self):
        # A missing user_id returns the ENTIRE proxy's usage. This must never
        # be reachable, so it is checked before the request is built.
        router = Router({})
        with patch("corliss.litellm.requests.request", router):
            with self.assertRaises(litellm.LiteLLMError):
                client().usage("", "2026-08-01", "2026-08-19")
        self.assertEqual(router.calls, [])


@override_settings(**LITELLM_SETTINGS)
class LifecycleTests(TestCase):
    """The two functions `membership.apply_event` calls. Neither may raise."""

    def setUp(self):
        cache.clear()

    def test_a_grant_provisions_the_user_into_their_tiers_team(self):
        router = Router({
            ("POST", "/user/new"): FakeResponse({}),
            ("GET", "/team/list"): FakeResponse(
                {"teams": [{"team_alias": "level-2", "team_id": "t-two"}]}
            ),
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": []}}),
            ("POST", "/team/member_add"): FakeResponse({}),
            ("GET", "/key/list"): FakeResponse({"keys": []}),
            ("POST", "/key/delete"): FakeResponse({}),
        })
        with patch("corliss.litellm.requests.request", router):
            self.assertTrue(litellm.on_membership_granted(MEMBER, "level-2"))
        self.assertEqual(
            router.bodies("POST", "/user/new")[0]["user_id"], MEMBER
        )

    def test_a_revocation_deletes_the_keys_before_touching_the_team(self):
        # The order is the point: if the second half fails the member has
        # already lost access, and a retry only finishes the paperwork.
        router = Router({
            ("GET", "/key/list"): FakeResponse({"keys": [key_row()]}),
            ("POST", "/key/delete"): FakeResponse({}),
            ("GET", "/user/info"): FakeResponse({"user_info": {"teams": ["t-two"]}}),
            ("POST", "/team/member_delete"): FakeResponse({}),
        })
        with patch("corliss.litellm.requests.request", router):
            self.assertTrue(litellm.on_membership_revoked(MEMBER))
        paths = [c[1] for c in router.calls]
        self.assertLess(paths.index("/key/delete"), paths.index("/team/member_delete"))

    def test_an_outage_is_reported_as_false_and_never_raised(self):
        # A push must not fail because LiteLLM is down: the grant already
        # happened in the registry, and sync_litellm is the repair.
        with patch("corliss.litellm.requests.request",
                   side_effect=requests.ConnectionError("down")):
            self.assertFalse(litellm.on_membership_granted(MEMBER, "level-2"))
            self.assertFalse(litellm.on_membership_revoked(MEMBER))

    def test_a_revocation_whose_team_removal_fails_still_reports_success(self):
        # The keys are gone, which is the half that matters.
        router = Router({
            ("GET", "/key/list"): FakeResponse({"keys": [key_row()]}),
            ("POST", "/key/delete"): FakeResponse({}),
            ("GET", "/user/info"): FakeResponse("boom", status_code=500),
        })
        with patch("corliss.litellm.requests.request", router):
            self.assertTrue(litellm.on_membership_revoked(MEMBER))

    @override_settings(LITELLM_URL="", LITELLM_PROVISIONER_KEY="")
    def test_unconfigured_lifecycle_hooks_do_nothing_quietly(self):
        with patch("corliss.litellm.requests.request") as request:
            self.assertFalse(litellm.on_membership_granted(MEMBER, "level-2"))
            self.assertFalse(litellm.on_membership_revoked(MEMBER))
        request.assert_not_called()


@override_settings(**LITELLM_SETTINGS)
class SyncCommandTests(TestCase):
    """`manage.py sync_litellm` — the repair for what the push is allowed to
    drop.

    The load-bearing assertion is that it exits non-zero on a member it could
    not align. A member missing from LiteLLM accrues no spend and reads as
    working from every direction, so a run that reported success over one would
    hide precisely the state the command exists to find.
    """

    def _row(self, did=MEMBER, *, active=True, tier="level-2"):
        return MembershipCache.objects.create(
            did=did, active=active, tier=tier,
            last_rkey=f"{did}:3lqx7qzabc2de",
            last_event_at="2026-01-01T00:00:00Z",
            author_did="did:plc:anadmin",
        )

    def run_command(self, **opts):
        out = StringIO()
        call_command("sync_litellm", stdout=out, stderr=out, **opts)
        return out.getvalue()

    def setUp(self):
        cache.clear()
        patcher = patch(
            "corliss.membership.handles_for", return_value={MEMBER: "alice.example"}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @override_settings(LITELLM_URL="", LITELLM_PROVISIONER_KEY="")
    def test_unconfigured_refuses_rather_than_reporting_success(self):
        with self.assertRaises(CommandError):
            self.run_command()

    def test_an_active_member_is_provisioned(self):
        self._row()
        with patch.object(litellm.LiteLLM, "ensure_user", return_value="t-two") as ensure:
            with patch.object(litellm.LiteLLM, "prune_foreign_keys", return_value=0):
                output = self.run_command()
        ensure.assert_called_once_with(MEMBER, handle="alice.example", tier="level-2")
        self.assertIn("provisioned 1", output)
        self.assertIn("complete", output)

    def test_keys_left_on_an_old_tiers_team_are_pruned_and_reported(self):
        # The drift a tier change leaves behind when this was not running:
        # LiteLLM will not re-team a key, so the stale ones have to go.
        self._row()
        with patch.object(litellm.LiteLLM, "ensure_user", return_value="t-two"):
            with patch.object(
                litellm.LiteLLM, "prune_foreign_keys", return_value=2
            ) as prune:
                output = self.run_command()
        prune.assert_called_once_with(MEMBER, "t-two")
        self.assertIn("pruned", output)
        self.assertIn("2 key(s) left on an old tier", output)

    def test_a_revoked_member_still_holding_keys_loses_them(self):
        self._row(active=False)
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[key_row()]):
            with patch.object(litellm, "on_membership_revoked") as revoked:
                output = self.run_command()
        revoked.assert_called_once_with(MEMBER)
        self.assertIn("revoked 1", output)

    def test_a_revoked_member_with_no_keys_is_already_current(self):
        # The common case after any previous run. Counting it as work done
        # would make every run look like it found something.
        self._row(active=False)
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
            with patch.object(litellm, "on_membership_revoked") as revoked:
                output = self.run_command()
        revoked.assert_not_called()
        self.assertIn("already current 1", output)

    def test_a_member_that_cannot_be_aligned_exits_non_zero(self):
        self._row()
        with patch.object(
            litellm.LiteLLM, "ensure_user",
            side_effect=litellm.LiteLLMError("no API tier for 'level-2'"),
        ):
            with self.assertRaises(CommandError) as caught:
                self.run_command()
        self.assertIn("could not be aligned", str(caught.exception))

    def test_one_failure_does_not_stop_the_rest_being_repaired(self):
        self._row(MEMBER)
        self._row(OTHER, tier="level-1")
        with patch.object(
            litellm.LiteLLM, "ensure_user",
            side_effect=[litellm.LiteLLMError("boom"), "t-one"],
        ) as ensure:
            with patch.object(litellm.LiteLLM, "prune_foreign_keys", return_value=0):
                with self.assertRaises(CommandError):
                    self.run_command()
        self.assertEqual(ensure.call_count, 2)

    def test_dry_run_changes_nothing_but_still_checks_the_tier_maps(self):
        # The one failure a preview can find, and the one that stops issuance.
        self._row()
        with patch.object(litellm.LiteLLM, "ensure_user") as ensure:
            with patch.object(litellm.LiteLLM, "team_id_for", return_value="t") as team:
                output = self.run_command(dry_run=True)
        ensure.assert_not_called()
        team.assert_called_once_with("level-2")
        self.assertIn("nothing was changed", output)

    def test_an_empty_cache_says_so_rather_than_reporting_success_quietly(self):
        # On a rebuilt cluster this means reconcile_membership has not run yet.
        output = self.run_command()
        self.assertIn("cache is empty", output)
