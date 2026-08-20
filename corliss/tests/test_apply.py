"""Applying for membership: writing the record into the applicant's own PDS.

The other half of `test_applications.py`. That one covers an admin reading the
queue out of the registry index; this one covers a person asking, which is a
write to their own repo and touches the registry not at all.

Four things here are load-bearing and none of them are obvious from the diff:

- **Applying confers nothing.** Every path below is asserted to leave
  `MembershipCache` alone. A record in someone's PDS is a request; only an
  admin's grant in the registry space is an answer, and if these two ever blur
  the result is self-service membership.
- **The applicant's own state comes from their PDS, never from the index.**
  The index lags the write by however long the firehose takes, so an applicant
  reading their own status from it would click the button and watch nothing
  happen.
- **A stale access token is the normal case, not an edge case.** Corliss's
  Django session outlives a PDS access token by a wide margin, so the
  refresh-and-retry path is what a member who signed in this morning takes when
  they apply this afternoon. It is tested as the main road.
- **"No record" and "could not ask" are different answers.** A PDS reports a
  missing record as HTTP 400 with `RecordNotFound`, so the status alone cannot
  tell them apart — and collapsing them would show the apply form to someone
  who has already applied.

Nothing here touches the network: `requests` is mocked at the boundary, in the
`FakeResp` style of `test_client.py`.
"""

from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from corliss import atproto, membership
from corliss.models import AtprotoToken, MembershipCache, User

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
PDS = "https://pds.example.com"
ISSUER = "https://auth.example"
TOKEN_ENDPOINT = "https://auth.example/token"

COLLECTION = membership.REQUEST_COLLECTION


class FakeResp:
    """A `requests.Response` stand-in — same shape as `test_client.py`'s."""

    def __init__(self, *, status=200, json_data=None, text="", headers=None):
        self.status_code = status
        self._json = json_data
        self.text = text
        self.headers = headers or {}
        self.ok = 200 <= status < 300

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError(f"status {self.status_code}")


class ClearsCache(TestCase):
    """Clears the application cache on the way in *and* on the way out.

    On the way out is the half that is easy to miss and bit once: the cache
    outlives a `TestCase`, these tests deliberately leave records in it, and the
    DID they use is the same one the rest of the suite signs in as. A test class
    that only cleared on entry left the next file's non-member looking like an
    applicant.
    """

    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)


def make_member(*, did=DID, handle="alice.bsky.social", with_token=True):
    user = User.objects.create_user(username=handle, did=did, pds_url=PDS)
    if with_token:
        AtprotoToken.objects.create(
            user=user,
            pds_url=PDS,
            issuer=ISSUER,
            token_endpoint=TOKEN_ENDPOINT,
            access_token="access-1",
            refresh_token="refresh-1",
            dpop_private_pem=atproto.key_to_pem(atproto.generate_key()),
        )
    return user


class NoteTests(TestCase):
    """The note is public and the lexicon caps it. Both facts are enforced here
    rather than at the PDS, because the PDS's refusal is a lexicon validation
    error the member cannot act on."""

    def test_a_normal_note_is_trimmed(self):
        self.assertEqual(membership.validate_note("  hello  "), "hello")

    def test_a_blank_note_is_fine_and_becomes_empty(self):
        self.assertEqual(membership.validate_note("   \n "), "")
        self.assertEqual(membership.validate_note(None), "")

    def test_too_many_characters_is_refused_with_the_count(self):
        with self.assertRaises(membership.ApplicationError) as caught:
            membership.validate_note("x" * 301)
        self.assertIn("301", str(caught.exception))
        self.assertIn("300", str(caught.exception))

    def test_the_byte_limit_catches_what_the_character_limit_does_not(self):
        # 300 four-byte characters is inside maxGraphemes and well past
        # maxLength, which is counted in UTF-8 bytes. Checking only one of the
        # two would let the PDS do the refusing.
        note = "𝄞" * 300
        self.assertEqual(len(note), 300)
        self.assertGreater(len(note.encode("utf-8")), membership.NOTE_MAX_BYTES)
        with self.assertRaises(membership.ApplicationError):
            membership.validate_note(note)


class FindRecordTests(TestCase):
    """`find_record` is the only place that can say "absent" rather than
    "unreachable", because the PDS carries that distinction in the body of an
    ordinary 400."""

    def setUp(self):
        self.doc = {
            "id": DID,
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": PDS,
                }
            ],
        }

    def _find(self, resp):
        with patch.object(atproto, "fetch_did_document", return_value=self.doc):
            with patch.object(requests, "get", return_value=resp):
                return atproto.find_record(DID, COLLECTION, "self")

    def test_a_record_comes_back_as_its_value(self):
        record = {"createdAt": "2026-08-17T13:44:05.472Z", "note": "hi"}
        self.assertEqual(self._find(FakeResp(json_data={"value": record})), record)

    def test_record_not_found_is_none_not_an_error(self):
        # The real shape, verified against a Bluesky PDS: HTTP 400, with the
        # reason in the body.
        self.assertIsNone(
            self._find(FakeResp(status=400, json_data={"error": "RecordNotFound"}))
        )

    def test_any_other_failure_still_raises(self):
        with self.assertRaises(atproto.OAuthError):
            self._find(FakeResp(status=500, json_data={"error": "InternalError"}))

    def test_get_record_still_treats_a_missing_record_as_a_failure(self):
        # The roster reads through `get_record`, and an unreadable roster must
        # never be mistaken for an empty one.
        with self.assertRaises(atproto.OAuthError):
            with patch.object(atproto, "find_record", return_value=None):
                atproto.get_record(DID, COLLECTION, "self")


class WriteRecordTests(TestCase):
    """Spending a member's tokens: the write, the refresh, and what is stored
    afterwards."""

    def setUp(self):
        self.user = make_member()
        self.token = self.user.atproto_token

    def test_a_successful_write_posts_the_record_to_the_members_own_repo(self):
        record = {"createdAt": "2026-08-20T00:00:00Z"}
        with patch.object(
            requests, "post", return_value=FakeResp(json_data={"uri": "at://x"})
        ) as post:
            atproto.write_record(self.user, COLLECTION, "self", record)

        url, kwargs = post.call_args[0][0], post.call_args[1]
        self.assertTrue(url.endswith("/xrpc/com.atproto.repo.putRecord"))
        self.assertEqual(
            kwargs["json"],
            {
                "repo": DID,
                "collection": COLLECTION,
                "rkey": "self",
                "record": record,
            },
        )
        # The member's token authorises it, bound to the session DPoP key.
        self.assertEqual(kwargs["headers"]["Authorization"], "DPoP access-1")
        self.assertIn("DPoP", kwargs["headers"])

    def test_a_server_nonce_is_honoured_and_remembered(self):
        responses = [
            FakeResp(
                status=401,
                json_data={"error": "use_dpop_nonce"},
                headers={"DPoP-Nonce": "server-nonce"},
            ),
            FakeResp(json_data={}, headers={"DPoP-Nonce": "server-nonce"}),
        ]
        with patch.object(requests, "post", side_effect=responses):
            atproto.write_record(self.user, COLLECTION, "self", {})

        self.token.refresh_from_db()
        self.assertEqual(self.token.dpop_nonce, "server-nonce")

    def test_a_stale_token_is_refreshed_and_the_write_retried_once(self):
        posts = [
            FakeResp(status=401, json_data={"error": "invalid_token"}),
            # The token endpoint, reached through `refresh_tokens`.
            FakeResp(
                json_data={
                    "access_token": "access-2",
                    "refresh_token": "refresh-2",
                    "expires_in": 3600,
                }
            ),
            FakeResp(json_data={"uri": "at://x"}),
        ]
        with patch.object(atproto, "build_client_assertion", return_value="assn"):
            with patch.object(requests, "post", side_effect=posts) as post:
                atproto.write_record(self.user, COLLECTION, "self", {})

        self.assertEqual(post.call_count, 3)
        self.assertTrue(post.call_args_list[1][0][0].endswith("/token"))
        self.assertEqual(
            post.call_args_list[1][1]["data"]["grant_type"], "refresh_token"
        )

        self.token.refresh_from_db()
        self.assertEqual(self.token.access_token, "access-2")
        # Rotated, not kept: atproto refresh tokens are single-use, and a client
        # that keeps the old one has ended the session at the next refresh.
        self.assertEqual(self.token.refresh_token, "refresh-2")
        self.assertIsNotNone(self.token.expires_at)
        self.assertGreater(self.token.expires_at, timezone.now())

    def test_it_retries_exactly_once(self):
        posts = [
            FakeResp(status=401, json_data={"error": "invalid_token"}),
            FakeResp(json_data={"access_token": "access-2"}),
            FakeResp(status=401, json_data={"error": "invalid_token"}),
        ]
        with patch.object(atproto, "build_client_assertion", return_value="assn"):
            with patch.object(requests, "post", side_effect=posts) as post:
                with self.assertRaises(atproto.OAuthError):
                    atproto.write_record(self.user, COLLECTION, "self", {})
        self.assertEqual(post.call_count, 3)

    def test_a_failed_refresh_raises_rather_than_writing(self):
        posts = [
            FakeResp(status=401, json_data={"error": "invalid_token"}),
            FakeResp(status=400, text="invalid_grant"),
        ]
        with patch.object(atproto, "build_client_assertion", return_value="assn"):
            with patch.object(requests, "post", side_effect=posts):
                with self.assertRaises(atproto.OAuthError):
                    atproto.write_record(self.user, COLLECTION, "self", {})

    def test_no_token_row_is_NoSession_not_a_crash(self):
        stranger = make_member(
            did="did:dev:bob", handle="bob", with_token=False
        )
        with self.assertRaises(atproto.NoSession):
            atproto.write_record(stranger, COLLECTION, "self", {})

    def test_no_refresh_token_is_NoSession_too(self):
        self.token.refresh_token = ""
        self.token.save(update_fields=["refresh_token"])
        with patch.object(
            requests,
            "post",
            return_value=FakeResp(status=401, json_data={"error": "invalid_token"}),
        ):
            with self.assertRaises(atproto.NoSession):
                atproto.write_record(self.user, COLLECTION, "self", {})


class MyApplicationTests(ClearsCache):
    """Reading your own application back — and caching it, since the nav asks
    on every render."""

    def test_a_record_is_returned_and_then_served_from_cache(self):
        record = {"createdAt": "2026-08-20T00:00:00Z", "note": "hi"}
        with patch.object(atproto, "find_record", return_value=record) as find:
            self.assertEqual(membership.my_application(DID), record)
            self.assertEqual(membership.my_application(DID), record)
        self.assertEqual(find.call_count, 1)

    def test_absence_is_cached_too(self):
        # Otherwise the common case — a visitor who has not applied — is the one
        # that pays a PDS round trip on every page.
        with patch.object(atproto, "find_record", return_value=None) as find:
            self.assertIsNone(membership.my_application(DID))
            self.assertIsNone(membership.my_application(DID))
        self.assertEqual(find.call_count, 1)

    def test_an_unreachable_pds_raises_rather_than_reading_as_no_application(self):
        with patch.object(
            atproto, "find_record", side_effect=atproto.OAuthError("down")
        ):
            with self.assertRaises(membership.ApplicationError):
                membership.my_application(DID)

    def test_refresh_bypasses_the_cache(self):
        with patch.object(atproto, "find_record", return_value=None) as find:
            membership.my_application(DID)
            membership.my_application(DID, refresh=True)
        self.assertEqual(find.call_count, 2)


class SubmitApplicationTests(ClearsCache):
    def setUp(self):
        super().setUp()
        self.user = make_member()

    def test_it_writes_the_lexicons_record_at_rkey_self(self):
        with patch.object(atproto, "write_record", return_value={}) as write:
            record = membership.submit_application(self.user, "  hello  ")

        user, collection, rkey, written = write.call_args[0]
        self.assertEqual(collection, COLLECTION)
        self.assertEqual(rkey, "self")  # the lexicon pins it
        self.assertEqual(written["$type"], COLLECTION)
        self.assertEqual(written["note"], "hello")
        self.assertTrue(written["createdAt"].endswith("Z"))
        self.assertEqual(record, written)

    def test_an_empty_note_is_omitted_rather_than_written_blank(self):
        with patch.object(atproto, "write_record", return_value={}) as write:
            membership.submit_application(self.user, "   ")
        self.assertNotIn("note", write.call_args[0][3])

    def test_the_fresh_record_is_cached_so_the_redirect_shows_pending(self):
        with patch.object(atproto, "write_record", return_value={}):
            record = membership.submit_application(self.user, "hi")
        # No `find_record` patch: a cache miss here would go to the network.
        self.assertEqual(membership.my_application(self.user.did), record)

    def test_a_bad_note_is_refused_before_anything_is_written(self):
        with patch.object(atproto, "write_record") as write:
            with self.assertRaises(membership.ApplicationError):
                membership.submit_application(self.user, "x" * 301)
        write.assert_not_called()

    def test_no_session_becomes_a_sentence_a_member_can_read(self):
        with patch.object(
            atproto, "write_record", side_effect=atproto.NoSession("nope")
        ):
            with self.assertRaises(membership.ApplicationError) as caught:
                membership.submit_application(self.user)
        self.assertIn("PDS", str(caught.exception))

    def test_applying_never_touches_the_membership_cache(self):
        with patch.object(atproto, "write_record", return_value={}):
            membership.submit_application(self.user, "let me in")
        self.assertEqual(MembershipCache.objects.count(), 0)
        self.assertFalse(membership.is_active_member(self.user.did))


class ApplyViewTests(ClearsCache):
    def setUp(self):
        super().setUp()
        self.user = make_member()

    def test_a_signed_out_visitor_is_sent_to_login(self):
        resp = self.client.post(reverse("apply"))
        self.assertRedirects(resp, reverse("login"), fetch_redirect_response=False)

    def test_get_is_refused(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("apply")).status_code, 405)

    def test_it_is_csrf_protected(self):
        # The test client waives CSRF by default, so this is the only place the
        # protection is actually exercised. It matters more here than on most
        # forms: a cross-site POST that landed would write a public record into
        # the member's own repo under their name.
        from django.test import Client

        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.user)
        with patch.object(atproto, "write_record") as write:
            resp = strict.post(reverse("apply"), {"note": "hi"})
        self.assertEqual(resp.status_code, 403)
        write.assert_not_called()

    def test_it_writes_and_redirects_home(self):
        self.client.force_login(self.user)
        with patch.object(atproto, "write_record", return_value={}) as write:
            resp = self.client.post(reverse("apply"), {"note": "hello"})
        self.assertRedirects(resp, reverse("home"), fetch_redirect_response=False)
        self.assertEqual(write.call_args[0][3]["note"], "hello")

    def test_a_member_is_refused_without_writing(self):
        MembershipCache.objects.create(
            did=DID,
            active=True,
            tier="level-0",
            last_rkey=f"{DID}:3lqx",
            last_event_at=timezone.now(),
            author_did="did:plc:admin",
        )
        self.client.force_login(self.user)
        with patch.object(atproto, "write_record") as write:
            resp = self.client.post(reverse("apply"))
        write.assert_not_called()
        self.assertRedirects(resp, reverse("home"), fetch_redirect_response=False)

    def test_a_failure_is_shown_on_the_next_page_and_only_once(self):
        self.client.force_login(self.user)
        with patch.object(
            atproto, "write_record", side_effect=atproto.OAuthError("boom")
        ):
            self.client.post(reverse("apply"), {"note": "hi"})

        with patch.object(atproto, "find_record", return_value=None):
            first = self.client.get(reverse("home"))
            second = self.client.get(reverse("home"))
        self.assertContains(first, "would not accept")
        self.assertNotContains(second, "would not accept")

    def test_a_failed_apply_leaves_the_membership_cache_alone(self):
        self.client.force_login(self.user)
        with patch.object(
            atproto, "write_record", side_effect=atproto.OAuthError("boom")
        ):
            self.client.post(reverse("apply"))
        self.assertEqual(MembershipCache.objects.count(), 0)


class HomePageStateTests(ClearsCache):
    """The four states the card renders, which are deliberately not two."""

    def setUp(self):
        super().setUp()
        self.user = make_member()
        self.client.force_login(self.user)

    def test_no_application_offers_the_form(self):
        with patch.object(atproto, "find_record", return_value=None):
            resp = self.client.get(reverse("home"))
        self.assertContains(resp, "Apply for membership")
        self.assertContains(resp, 'action="/membership/apply"')

    def test_the_note_is_one_line(self):
        # A box the size of a paragraph invites an essay into a field the
        # lexicon caps at 300 graphemes — and invites putting something in it
        # that the author may not have registered is world-readable.
        with patch.object(atproto, "find_record", return_value=None):
            resp = self.client.get(reverse("home"))
        self.assertContains(resp, 'name="note" type="text"')
        self.assertContains(resp, 'maxlength="300"')
        self.assertNotContains(resp, "<textarea")
        self.assertContains(resp, "public")

    def test_an_existing_application_shows_pending_and_hides_the_form(self):
        record = {"createdAt": "2026-08-17T13:44:05.472Z", "note": "HEYO"}
        with patch.object(atproto, "find_record", return_value=record):
            resp = self.client.get(reverse("home"))
        self.assertContains(resp, "Your application is in")
        self.assertContains(resp, "17 August 2026")
        self.assertContains(resp, "HEYO")
        self.assertNotContains(resp, 'action="/membership/apply"')

    def test_an_unreadable_date_still_counts_as_an_application(self):
        with patch.object(atproto, "find_record", return_value={"note": "hi"}):
            resp = self.client.get(reverse("home"))
        self.assertContains(resp, "Your application is in")
        self.assertNotContains(resp, 'action="/membership/apply"')

    def test_an_unreachable_pds_holds_the_form_back_rather_than_guessing(self):
        # Showing the form here would invite a second application over the
        # first, which is the one thing rkey `self` cannot protect against.
        with patch.object(
            atproto, "find_record", side_effect=atproto.OAuthError("down")
        ):
            resp = self.client.get(reverse("home"))
        self.assertContains(resp, "reach your PDS")
        self.assertNotContains(resp, 'action="/membership/apply"')

    def test_an_account_with_no_pds_is_told_so_and_asks_nothing(self):
        # `dev_login` is the only way to get here: those accounts complete no
        # handshake, so there is no repo to resolve and no point resolving one.
        dev = make_member(did="did:dev:bob", handle="bob", with_token=False)
        dev.pds_url = ""
        dev.save(update_fields=["pds_url"])
        self.client.force_login(dev)
        with patch.object(atproto, "find_record", return_value=None) as find:
            resp = self.client.get(reverse("home"))
        # Not `assert_not_called`: the nav's roster read goes through the same
        # function. The claim is narrower and the one that matters — nobody went
        # looking for an application in a repo we cannot locate.
        self.assertNotIn(
            COLLECTION, [call.args[1] for call in find.call_args_list]
        )
        self.assertContains(resp, "no connection to a PDS")
        self.assertNotContains(resp, 'action="/membership/apply"')


class NavForANonMemberTests(ClearsCache):
    """GATE's nav-side form: the member surfaces are visible and shut, not
    absent.

    Hiding them told a non-member nothing about what membership is for; linking
    them live — which is what Chat did — handed out a promise that breaks on the
    next click, since both pages refuse them anyway.
    """

    def setUp(self):
        super().setUp()
        self.user = make_member()
        self.client.force_login(self.user)
        patcher = patch.object(atproto, "find_record", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    @override_settings(CHAT_URL="https://chat.example.com")
    def test_a_non_member_sees_both_entries_and_can_open_neither(self):
        resp = self.client.get(reverse("home"))
        html = resp.content.decode()

        self.assertIn(">Chat</span>", html)
        self.assertIn(">API</span>", html)
        # The claim that matters: no way through. A span has no href, so this
        # also fails if either ever reverts to a bare <a>.
        self.assertNotIn('href="https://chat.example.com"', html)
        self.assertNotIn(f'href="{reverse("api")}"', html)

    @override_settings(CHAT_URL="https://chat.example.com")
    def test_a_member_gets_real_links(self):
        MembershipCache.objects.create(
            did=DID,
            active=True,
            tier="level-2",
            last_rkey=f"{DID}:3lqx",
            last_event_at=timezone.now(),
            author_did="did:plc:admin",
        )
        html = self.client.get(reverse("home")).content.decode()
        self.assertIn('href="https://chat.example.com"', html)
        self.assertIn(f'href="{reverse("api")}"', html)
        self.assertNotIn("nav__item--closed", html)

    @override_settings(CHAT_URL="")
    def test_chat_stays_hidden_when_it_is_not_deployed(self):
        # A closed door says "not for you yet". On a cluster with no chat, that
        # would be a different statement, and a false one.
        html = self.client.get(reverse("home")).content.decode()
        self.assertNotIn(">Chat</span>", html)
        self.assertIn(">API</span>", html)


class MembershipLabelTests(ClearsCache):
    """The nav's `Membership: …`, which is where pending shows up on every
    page."""

    def setUp(self):
        super().setUp()
        self.user = make_member()

    def test_an_applicant_reads_as_pending(self):
        with patch.object(atproto, "find_record", return_value={"createdAt": "x"}):
            self.assertEqual(self.user.membership_label, "pending")

    def test_no_application_reads_as_none(self):
        with patch.object(atproto, "find_record", return_value=None):
            self.assertEqual(self.user.membership_label, "none")

    def test_an_unreachable_pds_reads_as_none_rather_than_500ing_the_nav(self):
        with patch.object(
            atproto, "find_record", side_effect=atproto.OAuthError("down")
        ):
            self.assertEqual(self.user.membership_label, "none")

    def test_an_account_with_no_pds_asks_nothing_at_all(self):
        dev = make_member(did="did:dev:bob", handle="bob", with_token=False)
        dev.pds_url = ""
        with patch.object(atproto, "find_record") as find:
            self.assertFalse(dev.has_pending_application)
        find.assert_not_called()

    def test_a_member_with_no_pds_still_does_not_reach_for_one(self):
        # The guard is on `pds_url`, not on the DID method, so it holds for a
        # real account whose repo we have simply never resolved.
        self.user.pds_url = ""
        with patch.object(atproto, "find_record") as find:
            self.assertFalse(self.user.has_pending_application)
        find.assert_not_called()

    def test_a_member_reads_as_their_tier_without_asking_the_pds(self):
        # `membership_label` checks the grant first, so an active member costs
        # no PDS round trip — which matters, since the nav asks on every page.
        MembershipCache.objects.create(
            did=DID,
            active=True,
            tier="level-2",
            last_rkey=f"{DID}:3lqx",
            last_event_at=timezone.now(),
            author_did="did:plc:admin",
        )
        with patch.object(atproto, "find_record") as find:
            self.assertEqual(self.user.membership_label, "level 2")
        find.assert_not_called()


class ScopeTests(TestCase):
    """What Corliss asks a member for, and what it publishes asking for."""

    def test_the_repo_scope_is_narrow_and_covers_the_one_collection(self):
        self.assertIn(f"repo:{COLLECTION}", atproto.SCOPE)
        for action in ("create", "update", "delete"):
            self.assertIn(f"action={action}", atproto.SCOPE)

    def test_it_does_not_ask_for_blanket_repo_write(self):
        # `transition:generic` is "write any repository record type" — standing
        # permission to write anything at all into every member's repo, for the
        # sake of one record. The granular scope above is what scn-ops has asked
        # for in production.
        self.assertNotIn("transition:generic", atproto.SCOPE)

    def test_email_is_still_asked_for(self):
        # Dropping this would silently empty `User.email` on the next login.
        self.assertIn("transition:email", atproto.SCOPE)

    def test_the_published_metadata_declares_exactly_what_par_requests(self):
        # PAR fails with invalid_scope if these two ever disagree, and nothing
        # in the client raises first.
        self.assertEqual(atproto.client_metadata()["scope"], atproto.SCOPE)
