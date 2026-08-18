from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.db.models import OuterRef, Subquery

from corliss.models import MembershipCache, User


@admin.register(User)
class CorlissUserAdmin(UserAdmin):
    """Admin for the DID-keyed member model.

    Extends Django's UserAdmin so the standard auth fieldsets still work, and
    surfaces the atproto identity fields (`did`, `pds_url`, `last_seen`).
    """

    list_display = ("username", "did", "pds_url", "last_seen", "is_staff")
    search_fields = ("username", "did")
    readonly_fields = ("did", "last_seen", "last_login", "date_joined")

    # Add the atproto identity fields to UserAdmin's default fieldsets.
    fieldsets = UserAdmin.fieldsets + (
        ("ATProto identity", {"fields": ("did", "pds_url", "last_seen")}),
    )


@admin.register(MembershipCache)
class MembershipCacheAdmin(admin.ModelAdmin):
    """Read-only view of the membership cache.

    Deliberately not editable — not even by a superuser. `MembershipCache` is a
    cached computation over the registry's grant and revocation events, and the
    model's own contract is that nothing writes here except a registry event.
    An edit made here would be silently reverted by the next push or reconcile,
    or (worse) would look like membership until it was. The registry is where
    membership is changed; this page is where you look at what arrived.

    Delete is off for the same reason. Removing an orphaned row is a deliberate
    act with a real decision behind it — see the orphans section of the console
    at `/manage/` — not a row-select and a dropdown.
    """

    list_display = ("handle", "did", "active", "tier", "last_event_at", "author_did")
    list_filter = ("active", "tier")
    search_fields = ("did", "author_did")
    ordering = ("-active", "did")
    readonly_fields = (
        "did",
        "active",
        "tier",
        "last_rkey",
        "last_event_at",
        "author_did",
        "updated_at",
    )

    def get_queryset(self, request):
        """Attach the local handle, if the member has ever signed in here.

        A subquery rather than a lookup per row: the cache is keyed by DID with
        no FK to `User` (a grant can precede the account), so there is no
        `select_related` to reach for. Local only — no DID-document read, since
        an admin list must not depend on the network to render.
        """
        return super().get_queryset(request).annotate(
            handle=Subquery(
                User.objects.filter(did=OuterRef("did")).values("username")[:1]
            )
        )

    @admin.display(description="Handle", ordering="handle")
    def handle(self, obj):
        # Blank means "granted, never signed in" — the INVITE case, not an error.
        return obj.handle or "—"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
