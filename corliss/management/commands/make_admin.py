"""Make (or unmake) a cluster admin, keyed on DID.

  manage.py make_admin alice.bsky.social
  manage.py make_admin alice.bsky.social --did did:plc:abc123   # skip resolution
  manage.py make_admin alice.bsky.social --remove
  manage.py make_admin alice.bsky.social --admit            # not a member yet
  manage.py make_admin alice.bsky.social --admit --tier level-2

**One kind of admin.** Being an admin means a current entry on the
registry's public roster — that is the authority, the thing
scn-member-registry's Lua checks before it will accept a grant — and an admin
can do everything, Django's `/admin/` included. So appointing also sets
`is_staff` and `is_superuser` on their row, as copies of the roster; the
Django admin still asks the roster on every request (`corliss.admin_site`).
This command and the button on `/manage/` both call `membership.appoint_admin`.

The roster is written **first**. If that fails nothing has changed, rather than
leaving somebody holding a Django flag the registry has never heard of.

This command needs the **service account's stored session**, because the roster
lives in that account's own repo and atproto has no cross-repo write. Sign in
to Corliss once as `SCN_SERVICE_DID` to establish it; the error says so if it
is missing. On a network with no roster record at all, that same sign-in is
also how the first roster gets written — see `membership.is_cluster_admin`.

Two doors this does *not* open, listed because they look like this one:

- **The break-glass Django account** — `ensure_admin`, local password, no
  atproto identity. Unrelated to the roster and untouched here.
- **Member** — `MembershipCache`, written only by the registry's events. Admin
  does not imply member and never has: an admin with no grant reaches Corliss
  and receives no tier and no API key.

Admins are members, so by default this refuses anyone who is not one. `--admit`
is the one way to do both from a shell: it first grants membership at `--tier`,
authored by the service account (see `membership.admit_member`), and only then
appoints. It is opt-in because admitting someone is a decision of its own, and
a command that did it silently would make "make them an admin" also mean "let
them in". Someone who is already a member is left at the tier they have.

Resolves the handle to a DID (DNS TXT, then HTTPS well-known — see
corliss.atproto.resolve_handle_for_admin) and verifies it by checking the DID
document's alsoKnownAs actually lists that handle, unless --did is given, which
trusts the operator and skips both steps.

Keys on `did` — the same field corliss.views._upsert_member keys on — so a
later ATProto OAuth login with this DID lands on the exact row this touches. No
password is ever set here (set_unusable_password on creation): the row only
ever authenticates via ATProto OAuth.
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from corliss import atproto, membership

User = get_user_model()


class Command(BaseCommand):
    help = (
        "Make an ATProto handle a cluster admin: a current entry on the "
        "registry roster, which makes them a Django superuser too. --remove "
        "reverses it."
    )

    def add_arguments(self, parser):
        parser.add_argument("handle", help="ATProto handle, e.g. alice.bsky.social")
        parser.add_argument(
            "--did",
            default=None,
            help="Skip handle resolution/verification; use this DID directly.",
        )
        parser.add_argument(
            "--remove",
            action="store_true",
            help=(
                "End their admin authority instead of granting it. Members "
                "they approved stay members."
            ),
        )
        parser.add_argument(
            "--admit",
            action="store_true",
            help=(
                "If they are not a member yet, grant membership first (at "
                "--tier), authored by the service account. Without this, a "
                "non-member is refused."
            ),
        )
        parser.add_argument(
            "--tier",
            default=membership.DEFAULT_TIER,
            help=(
                "The tier --admit grants. Ignored for someone who is already "
                f"a member. Default: {membership.DEFAULT_TIER}."
            ),
        )

    def handle(self, *args, **opts):
        handle = opts["handle"].strip().lstrip("@")
        did = self._resolve(handle, opts["did"])

        # The actor. A command run on the server has no signed-in admin behind
        # it, and recording the person who typed it is not something the shell
        # can prove — so the roster entry is attributed to the account that
        # actually performs the write, which is the honest answer.
        from django.conf import settings

        actor_did = settings.SCN_SERVICE_DID

        admitted = ""
        try:
            if opts["remove"]:
                note = membership.dismiss_admin(actor_did, did)
                verb = "removed"
            else:
                if opts["admit"]:
                    # Before the roster write, and reported on its own line: if
                    # the appointment then fails, the operator still learns the
                    # membership half happened.
                    admitted = membership.admit_member(did, opts["tier"])
                    self.stdout.write(f"{handle!r} ({did}) — {admitted}")
                note = membership.appoint_admin(actor_did, did)
                verb = "promoted"
        except (membership.RosterError, membership.RegistryError) as exc:
            raise CommandError(str(exc)) from exc

        # "promoted" is load-bearing: zai-ops' `make-admin.yml` reads it out of
        # stdout to decide whether the run changed anything.
        self.stdout.write(
            self.style.SUCCESS(f"{verb} {handle!r} ({did}) — cluster admin")
        )
        if note:
            self.stdout.write(self.style.WARNING(f"  {note}"))

        self._report_scope(did)

    def _resolve(self, handle, given):
        if given:
            return given.strip()
        try:
            did = atproto.resolve_handle_for_admin(handle)
            doc = atproto.fetch_did_document(did)
        except atproto.OAuthError as exc:
            raise CommandError(str(exc)) from exc
        resolved_handle = atproto.handle_from_doc(doc)
        if resolved_handle != handle:
            raise CommandError(
                f"DID document for {did} does not list handle {handle!r} "
                f"in alsoKnownAs (found {resolved_handle!r})"
            )
        return did

    def _report_scope(self, did):
        """Say what the registry will actually accept, which can lag."""
        if not User.objects.filter(did=did).exists():
            self.stdout.write(
                "  No local row yet — it is created with the right flags on "
                "their first sign-in."
            )
        self.stdout.write(
            "  The registry reads this roster through its own index, so it can "
            "be a minute before they can approve anyone."
        )
