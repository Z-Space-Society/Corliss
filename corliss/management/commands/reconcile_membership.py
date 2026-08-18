"""Rebuild the membership cache from the registry.

  manage.py reconcile_membership
  manage.py reconcile_membership --dry-run

The push keeps the cache fresh; this is what *builds* it. A Corliss rebuilt from
nothing has witnessed no pushes and never will — those events already happened —
so this command is the only route by which membership can re-enter it. That is
why it needs no login and no `User` rows: `MembershipCache` is keyed by DID, so
it can repopulate a database nobody has ever signed in to.

**Exits non-zero when the report is not complete.** An `unresolved` DID is a
member missing from the cache and an `orphan` is a row the registry cannot
account for; both are the failure a gate must never be handed. A scheduled run
that logged "done" over either would be worse than not running at all.
"""

from django.core.management.base import BaseCommand, CommandError

from corliss import membership


class Command(BaseCommand):
    help = "Re-derive MembershipCache from the registry's grant and revocation records."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change without writing anything.",
        )

    def handle(self, *args, **opts):
        dry_run = opts["dry_run"]
        registry = membership.MembershipRegistry.from_settings()

        try:
            report = registry.reconcile(dry_run=dry_run)
        except (membership.RegistryError, membership.ReconcileError) as exc:
            # Both mean "the answer would not be trustworthy", which is a
            # different thing from "the answer is bad news" below.
            raise CommandError(str(exc)) from exc

        if dry_run:
            self.stdout.write(self.style.WARNING("dry run — nothing was written"))

        self.stdout.write(
            f"applied {len(report.applied)}, unchanged {len(report.unchanged)}, "
            f"unresolved {len(report.unresolved)}, orphans {len(report.orphans)}"
        )

        for did in report.applied:
            self.stdout.write(f"  applied   {did}")

        for item in report.unresolved:
            self.stdout.write(
                self.style.ERROR(
                    f"  UNRESOLVED {item['did']} ({item['rkey']}): {item['error']}"
                )
            )

        for item in report.orphans:
            state = f"active {item['tier']}" if item["active"] else "revoked"
            self.stdout.write(
                self.style.ERROR(
                    f"  ORPHAN     {item['did']} ({state}), "
                    f"author {item['author_did']}"
                )
            )

        if not report.is_complete:
            # Not a crash — the run worked. The cache is just not something
            # anything may be gated on yet, and a caller has to be able to tell.
            raise CommandError(
                "reconciliation is incomplete: "
                f"{len(report.unresolved)} unresolved, {len(report.orphans)} orphans. "
                "An unresolved DID is a member absent from the cache; an orphan is "
                "a row the registry does not account for. Neither is safe to gate on."
            )

        self.stdout.write(self.style.SUCCESS("complete — the cache matches the registry"))
