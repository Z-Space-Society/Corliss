"""Stubs for the three edges a roster edit touches.

Not named `test_*`, so the runner does not collect it — this is shared setup,
used by both the console tests and the `make_admin` tests. They exercise the
same two functions (`membership.appoint_admin` / `dismiss_admin`), so stubbing
them the same way is what keeps the CLI and the button honest about being one
operation.

Stubbed at the *edges* rather than at `appoint_admin` itself: the read, the
write and the space call are mocked, and everything between them — the
already-an-admin check, the last-admin guard, the stamping — is the real code.

The PDS is modelled well enough to matter: a write is visible to the next read,
because a roster edit is a read-modify-write and a stub that forgot the write
would hide exactly the bugs that shape has.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

from corliss import atproto, membership
from corliss.models import AtprotoToken, MembershipCache

User = get_user_model()

SERVICE_DID = "did:plc:n4mzxx6z4ehnswc7znswtfr2"
OTHER_ADMIN = "did:plc:tmxbvcho3zysvtadtextctxw"
PDS = "https://pds.example.test"

GENESIS = "2026-01-01T00:00:00Z"


class RosterWriteMixin:
    """Give a test a writable roster and a live service session.

    Set `self.roster_entries` to reshape the starting roster, or to `None` for
    a network that has never had a roster record at all.
    """

    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

        self.service_user = User.objects.create_user(
            username="sharedcomputer.network", did=SERVICE_DID
        )
        # A *fully* live session: PDS tokens and a registered registry session.
        # Those two expire independently and only the second lets
        # `set_space_access` run, so leaving `registry_session_at` unset would
        # quietly make every appointment in every test take the degraded path.
        AtprotoToken.objects.create(
            user=self.service_user,
            pds_url=PDS,
            issuer=PDS,
            token_endpoint=f"{PDS}/oauth/token",
            access_token="service-access-token",
            dpop_private_pem="-----BEGIN PRIVATE KEY-----stub-----",
            registry_session_at=timezone.now(),
        )

        # Two entries, so a removal in a test is not automatically the
        # last-admin case and has to be asked for deliberately.
        self.roster_entries = [
            {"did": SERVICE_DID, "addedAt": GENESIS},
            {"did": OTHER_ADMIN, "addedAt": GENESIS},
        ]
        self.written = []
        # The sitting admin is a member, as the rule requires. The service
        # account deliberately is not — it holds authority and no grant, which
        # is why it never appears on the console's member table.
        self.grant(OTHER_ADMIN)

        find = patch.object(atproto, "find_record", side_effect=self._find_record)
        self.find_record = find.start()
        self.addCleanup(find.stop)

        write = patch.object(atproto, "write_record", side_effect=self._write_record)
        self.write_record = write.start()
        self.addCleanup(write.stop)

        space = patch.object(
            membership.MembershipRegistry,
            "set_space_access",
            return_value={"ok": True, "member": True},
        )
        self.set_space_access = space.start()
        self.addCleanup(space.stop)

    def grant(self, did, *, tier="level-2"):
        """Make `did` an active member.

        Needed by anything that appoints: admins are members, enforced in
        `appoint_admin`, so a test that skips this is testing the refusal
        whether it meant to or not.
        """
        return MembershipCache.objects.update_or_create(
            did=did,
            defaults={
                "active": True,
                "tier": tier,
                "last_rkey": f"{did}:3lqx",
                "last_event_at": timezone.now(),
                "author_did": OTHER_ADMIN,
            },
        )[0]

    def _find_record(self, did, collection, rkey):
        if self.roster_entries is None:
            # What a PDS reports for a record that was never written, which
            # `find_record` turns into None rather than an error.
            return None
        return {"admins": list(self.roster_entries), "updatedAt": GENESIS}

    def _write_record(self, user, collection, rkey, record):
        self.written.append(record)
        self.roster_entries = record["admins"]
        return {}

    def _written_entry(self, did):
        """The entry for `did` in the most recent write, or None."""
        if not self.written:
            return None
        for entry in reversed(self.written[-1]["admins"]):
            if entry.get("did") == did:
                return entry
        return None

    def _current_dids(self):
        """Who the most recent write leaves holding authority."""
        if not self.written:
            return []
        return [
            e["did"]
            for e in self.written[-1]["admins"]
            if e.get("removedAt") is None
        ]
