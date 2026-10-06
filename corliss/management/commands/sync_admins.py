"""Bring this app's own admin state back in line with the roster.

  manage.py sync_admins

`make_admin` changes who is an admin and writes every half as it goes. This
changes nobody: it re-asserts, for the roster as it stands, the one thing
Corliss keeps a copy of — the `is_staff` mirror (`membership.sync_staff_mirror`).
It exists for zai-ops' `scn-config`, whose Cluster Admins entry applies the
roster to everything that holds a copy of it, and Corliss is one of those.

Needs no service session: it reads the public roster and writes local rows.

**Registry space access is not touched.** That is the registry's state, set by
`make_admin` and the console button, and re-asserting it needs the service
account's registry session. A command that sometimes could and sometimes could
not would make "applied" mean two things.

Says what changed, one line per person, or that nothing did — the caller shows
the output as it is.
"""

from django.core.management.base import BaseCommand, CommandError

from corliss import membership


class Command(BaseCommand):
    help = "Re-derive every is_staff flag from the admin roster. Changes no admins."

    def handle(self, *args, **opts):
        try:
            granted, cleared = membership.sync_staff_mirror()
        except membership.RosterError as exc:
            raise CommandError(str(exc)) from exc

        handles = membership.handles_for(granted + cleared)
        for did in granted:
            self.stdout.write(f"{handles.get(did, did)}: marked as an admin")
        for did in cleared:
            self.stdout.write(f"{handles.get(did, did)}: no longer marked as an admin")
        if not granted and not cleared:
            self.stdout.write("Corliss already matches the roster.")
