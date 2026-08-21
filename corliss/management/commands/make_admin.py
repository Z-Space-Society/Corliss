"""Give an ATProto handle access to **Django's** admin, keyed on DID.

  manage.py make_admin alice.bsky.social
  manage.py make_admin alice.bsky.social --did did:plc:abc123   # skip resolution

**This does not make anyone a cluster admin, and it is not how membership
works.** Three doors look like one here, and only the first is this command's:

- **Django `/admin/`** — `is_staff`, which this sets. Corliss's own OIDC client
  config and session tables live behind it.
- **Cluster admin** — a live read of the public admin roster
  (`membership.is_cluster_admin`), stored nowhere and granted by editing the
  roster in the registry. `User.is_cluster_admin` never consults `is_staff` or
  `is_superuser`.
- **Member** — `MembershipCache`, written only by the registry's push.

So this command is **optional on a rebuild**: `views._upsert_member` does
`get_or_create(did=…)`, so a first ATProto login creates its own `User` row, and
`ensure_admin`'s break-glass account already covers Django's admin for the case
where nothing else works.

`is_superuser` is **not** granted by default, and `--superuser` exists only for
the operator who means it. That flag bypasses every permission check, so setting
it on an ATProto identity means a compromised ATProto session opens the Django
admin with nothing left to stop it. Staff alone opens the admin with whatever
permissions the row has been given, which by default is nothing — grant the
specific model permissions the person actually needs.

Resolves the handle to a DID (DNS TXT, then HTTPS well-known — see
corliss.atproto.resolve_handle_for_admin) and verifies it by checking the DID
document's alsoKnownAs actually lists that handle, unless --did is given,
which trusts the operator and skips both steps entirely.

Keys on `did` — the same field corliss.views._upsert_member keys on — so a
later ATProto OAuth login with this DID lands on the exact row this command
creates or promotes. No password is ever set here (set_unusable_password on
creation): this row only ever authenticates via ATProto OAuth.
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from corliss import atproto

User = get_user_model()


class Command(BaseCommand):
    help = (
        "Give an ATProto handle access to Django's admin (is_staff), keyed on "
        "DID. Cluster admin comes from the registry roster, not from here."
    )

    def add_arguments(self, parser):
        parser.add_argument("handle", help="ATProto handle, e.g. alice.bsky.social")
        parser.add_argument(
            "--did",
            default=None,
            help="Skip handle resolution/verification; use this DID directly.",
        )
        parser.add_argument(
            "--superuser",
            action="store_true",
            help=(
                "Also set is_superuser, which bypasses every permission check. "
                "Not needed for cluster admin, and rarely what you want."
            ),
        )

    def handle(self, *args, **opts):
        handle = opts["handle"].strip().lstrip("@")
        did = opts["did"]

        if did:
            did = did.strip()
        else:
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

        superuser = opts["superuser"]

        user, created = User.objects.get_or_create(
            did=did,
            defaults={
                "username": handle,
                "is_staff": True,
                "is_superuser": superuser,
            },
        )

        if created:
            user.set_unusable_password()
            user.save(update_fields=["password"])
            self.stdout.write(
                self.style.SUCCESS(f"created staff user {handle!r} ({did})")
            )
            self._report_scope(user)
            return

        changed_fields = []
        if user.username != handle:
            user.username = handle
            changed_fields.append("username")
        if not user.is_staff:
            user.is_staff = True
            changed_fields.append("is_staff")
        # Only ever granted on request. Never *withdrawn* here either: a command
        # that silently demoted the account an operator is currently using would
        # be a worse surprise than the one it is fixing. `--superuser` off is
        # "do not grant", not "revoke".
        if superuser and not user.is_superuser:
            user.is_superuser = True
            changed_fields.append("is_superuser")

        if changed_fields:
            user.save(update_fields=changed_fields)
            self.stdout.write(
                # "promoted" is load-bearing: zai-ops' `make-admin.yml` reads it
                # out of stdout to decide whether the run changed anything.
                self.style.SUCCESS(f"promoted {handle!r} ({did}) to Django staff")
            )
        else:
            self.stdout.write(f"{handle!r} ({did}) already has Django admin access")
        self._report_scope(user)

    def _report_scope(self, user):
        """Say what was actually granted, and what it is not.

        The command used to hand out `is_superuser` under the name "admin",
        which is the confusion worth spending three lines to prevent: someone
        running this to give a person cluster admin has done nothing of the
        kind, and someone running it with `--superuser` has done rather more
        than they may realise.
        """
        if user.is_superuser:
            self.stdout.write(
                self.style.WARNING(
                    "  is_superuser is set: this row bypasses every permission "
                    "check in Django."
                )
            )
        self.stdout.write(
            "  This is Django's admin only. Cluster admin is read live from the "
            "registry's roster; add them there instead."
        )
