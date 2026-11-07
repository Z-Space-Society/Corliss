"""Send the sync relay every workspace's roster and every member's name.

  manage.py sync_relay_rosters

The receivers in `corliss.signals` push each change as it commits; this is
what *repairs* the relay's copy. Run it once before the relay starts checking
rosters, so no workspace locks for want of one, and again after any stretch
when the relay could not be reached, since a push that failed then is not
retried.

Sends the whole of both, never a difference, so running it twice is the same
as once.

**Exits non-zero when anything could not be sent.** A run that reported
success over a missing roster would hide a workspace its members cannot open.
"""

from django.core.management.base import BaseCommand, CommandError

from corliss import sync_relay
from corliss.models import User, Workspace


class Command(BaseCommand):
    help = "Push every workspace roster and member name to the sync relay."

    def handle(self, *args, **options):
        if not sync_relay.is_configured():
            raise CommandError(
                "SYNC_RELAY_URL and SYNC_RELAY_SERVICE_TOKEN must be set."
            )

        failed = 0
        workspaces = list(Workspace.objects.order_by("pk").values_list("pk", flat=True))
        for pk in workspaces:
            try:
                sync_relay.push_workspace_members(pk)
            except sync_relay.SyncRelayError:
                failed += 1

        members = User.objects.order_by("did").values_list(
            "did", "username", "display_name"
        )
        sent = 0
        for did, handle, name in members:
            try:
                sync_relay.push_member(did, handle, name)
                sent += 1
            except sync_relay.SyncRelayError:
                failed += 1

        self.stdout.write(
            f"Pushed {len(workspaces)} rosters and {sent} members' names; {failed} failed."
        )
        if failed:
            raise CommandError(f"{failed} pushes failed; see the log.")
