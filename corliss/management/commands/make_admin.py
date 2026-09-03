"""Make (or unmake) a cluster admin, keyed on DID.

  manage.py make_admin alice.bsky.social
  manage.py make_admin alice.bsky.social --did did:plc:abc123   # skip resolution
  manage.py make_admin alice.bsky.social --remove

**One "admin", two halves, written together.** Being an admin means a current
entry on the registry's public roster — that is the authority, the thing
scn-member-registry's Lua checks before it will accept a grant — and
`is_staff`, which opens Django's `/admin/`. This command writes both, and so
does the button on `/manage/`; both call `membership.appoint_admin`. Making
them one operation is the point: two ways to be an admin was one too many.

The roster is written **first**. If that fails nothing has changed, rather than
leaving somebody holding a Django flag the registry has never heard of.

`is_superuser` is **not** granted, and `--superuser` exists only for the
operator who means it. That flag bypasses every permission check, so setting it
on an ATProto identity means a compromised ATProto session opens the Django
admin with nothing left to stop it. Plain `is_staff` opens the admin with
whatever model permissions the row has, which by default is none.

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
        "registry roster, plus Django's is_staff. --remove reverses it."
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
            "--superuser",
            action="store_true",
            help=(
                "Also set is_superuser, which bypasses every permission check. "
                "Rarely what you want."
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

        try:
            if opts["remove"]:
                note = membership.dismiss_admin(actor_did, did)
                verb = "removed"
            else:
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

        if opts["superuser"] and not opts["remove"]:
            self._grant_superuser(did, handle)
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

    def _grant_superuser(self, did, handle):
        """Escalate an existing row, or create one carrying the flag.

        Separate from the roster write above because it is a different
        authority with a different blast radius, asked for explicitly. Never
        *withdrawn* here: a command that silently demoted the account an
        operator is currently using would be a worse surprise than the one it
        is fixing.
        """
        user, created = User.objects.get_or_create(
            did=did,
            defaults={"username": handle, "is_staff": True, "is_superuser": True},
        )
        if created:
            user.set_unusable_password()
            user.save(update_fields=["password"])
        elif not user.is_superuser:
            user.is_superuser = True
            user.save(update_fields=["is_superuser"])
        self.stdout.write(
            self.style.WARNING(
                "  is_superuser is set: this row bypasses every permission "
                "check in Django."
            )
        )

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
