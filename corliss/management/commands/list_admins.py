"""Print the current cluster admins as JSON.

  manage.py list_admins

The read-only sibling of `make_admin`, for tooling that has to show who the
admins are without a browser — zai-ops' `scn-config` is the caller this exists
for. It reads the same roster `/manage/` does (`membership.fetch_roster`), so
the two cannot disagree about who is on it.

JSON, not a table, because the caller is a program. One object:

  roster_exists   false on a network where no roster record has been written
                  yet; the service account is then the sole admin by the
                  bootstrap rule (`membership.is_cluster_admin`) and `admins`
                  is empty.
  admins          one entry per CURRENT admin: did, handle, added_at, member
                  (holds a live grant) and is_staff (the local mirror).
  service         `membership.service_session_status()` — whether the session
                  every roster edit depends on is there. An add or remove will
                  fail without it, so a caller can say so before trying.

`member` and `is_staff` are reported rather than assumed because either can
lag the roster: an admin who was appointed before the member rule, or whose
local row has not been created yet, is still an admin.
"""

import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from corliss import membership

User = get_user_model()


class Command(BaseCommand):
    help = "Print the current cluster admins, and the service session, as JSON."

    def handle(self, *args, **opts):
        try:
            # Fresh, not the cached copy: this is asked right after an edit as
            # often as not, and a stale answer there reads as a failed edit.
            roster = membership.fetch_roster(refresh=True)
        except membership.RosterError as exc:
            raise CommandError(str(exc)) from exc

        # One entry per person: a re-added admin has two terms on the roster
        # and the current one is the term that says when this authority began.
        current = {e.did: e for e in roster.entries if e.is_current}
        handles = membership.handles_for(current)
        staff = set(
            User.objects.filter(did__in=current, is_staff=True).values_list(
                "did", flat=True
            )
        )
        admins = [
            {
                "did": did,
                "handle": handles.get(did, did),
                "added_at": entry.added_at.isoformat(),
                "member": membership.is_active_member(did),
                "is_staff": did in staff,
            }
            for did, entry in sorted(
                current.items(), key=lambda item: item[1].added_at
            )
        ]

        self.stdout.write(
            json.dumps(
                {
                    "roster_exists": roster.exists,
                    "admins": admins,
                    "service": membership.service_session_status(),
                },
                # The session status carries datetimes.
                default=lambda value: value.isoformat(),
                indent=2,
            )
        )
