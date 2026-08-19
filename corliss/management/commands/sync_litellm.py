"""Make LiteLLM agree with the membership cache.

  manage.py sync_litellm
  manage.py sync_litellm --dry-run

The push provisions LiteLLM as grants and revocations arrive; this is what
*repairs* it. Two failures make that necessary, and neither is hypothetical:

- **Provisioning is not atomic with the grant.** `apply_event` notifies LiteLLM
  after the cache row commits, and that notification is allowed to fail — a
  LiteLLM outage must not turn a push into an error for a grant that already
  happened in the registry. The cost of that choice is a member with a grant and
  no LiteLLM user, and this is what settles it.
- **A rebuilt cluster has a rebuilt LiteLLM.** `reconcile_membership` re-derives
  the cache from the registry; this re-derives LiteLLM from the cache. Run in
  that order, a flashed cluster gets its members back all the way down.

Reads the cache, never the registry. That keeps the two repairs separable: if
membership itself is wrong, `reconcile_membership` is the fix and running this
first would faithfully reproduce the wrong answer into LiteLLM.

**Exits non-zero when anything could not be aligned.** A scheduled run that
logged success over a member with no LiteLLM user would hide exactly the state
it exists to catch — the member's spend silently no-ops and everything looks
fine until someone asks why their usage is zero.
"""

from django.core.management.base import BaseCommand, CommandError

from corliss import litellm, membership
from corliss.models import MembershipCache


class Command(BaseCommand):
    help = "Align LiteLLM users, teams and keys with the membership cache."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change without touching LiteLLM.",
        )

    def handle(self, *args, **opts):
        dry_run = opts["dry_run"]
        client = litellm.LiteLLM.from_settings()

        if not client.is_configured:
            raise CommandError(
                "LiteLLM is not configured: LITELLM_URL and "
                "LITELLM_PROVISIONER_KEY must both be set"
            )

        rows = list(MembershipCache.objects.order_by("-active", "did"))
        if not rows:
            # Not an error, and worth saying out loud: on a rebuilt cluster this
            # means reconcile_membership has not run yet, and syncing an empty
            # cache into LiteLLM would be a no-op that reads as success.
            self.stdout.write(
                self.style.WARNING(
                    "the membership cache is empty — run reconcile_membership "
                    "first, or there is nothing here to reproduce"
                )
            )

        # Display only, and batched: one pass for every DID rather than a
        # lookup per member. See `membership.handles_for`.
        handles = membership.handles_for([row.did for row in rows])

        provisioned, revoked, unchanged, failures, pruned = [], [], [], [], []

        for row in rows:
            did = row.did
            try:
                if row.active:
                    if dry_run:
                        # Answered without writing: does the tier this member
                        # holds even map to a team? That is the one failure a
                        # preview can find, and the one that stops issuance.
                        client.team_id_for(row.tier)
                        provisioned.append(did)
                        continue
                    team_id = client.ensure_user(
                        did, handle=handles.get(did, ""), tier=row.tier
                    )
                    # A key minted under a previous tier still carries that
                    # tier's access — LiteLLM will not re-team a key — so a
                    # member whose tier moved while this was not running is
                    # exactly the drift worth repairing here.
                    stale = client.prune_foreign_keys(did, team_id)
                    if stale:
                        pruned.append((did, stale))
                    provisioned.append(did)
                else:
                    # A revoked row whose keys are already gone is the common
                    # case — every previous run left it that way — so it is
                    # counted as unchanged rather than reported as work done.
                    held = client.keys_for(did)
                    if not held:
                        unchanged.append(did)
                        continue
                    if not dry_run:
                        litellm.on_membership_revoked(did)
                    revoked.append((did, len(held)))
            except litellm.LiteLLMError as exc:
                failures.append((did, str(exc)))

        if dry_run:
            self.stdout.write(self.style.WARNING("dry run — nothing was changed"))

        self.stdout.write(
            f"provisioned {len(provisioned)}, revoked {len(revoked)}, "
            f"already current {len(unchanged)}, failed {len(failures)}"
        )

        for did, count in pruned:
            self.stdout.write(
                f"  pruned     {did} ({count} key(s) left on an old tier)"
            )

        for did, count in revoked:
            self.stdout.write(f"  revoked    {did} ({count} key(s))")

        for did, error in failures:
            self.stdout.write(self.style.ERROR(f"  FAILED     {did}: {error}"))

        if failures:
            raise CommandError(
                f"{len(failures)} member(s) could not be aligned with LiteLLM. "
                "A member missing from LiteLLM accrues no spend and reads as "
                "working, so this is not safe to leave."
            )

        self.stdout.write(
            self.style.SUCCESS("complete — LiteLLM matches the membership cache")
        )
