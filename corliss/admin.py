from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.db.models import OuterRef, Subquery

from corliss.models import MembershipCache, OidcSession, User


@admin.register(User)
class CorlissUserAdmin(UserAdmin):
    """Admin for the DID-keyed member model.

    Extends Django's UserAdmin so password management and the permissions
    machinery still work, but **declares `fieldsets` outright rather than
    appending to `UserAdmin.fieldsets`.**

    Appending is what used to leave `first_name` and `last_name` on the form.
    They come free with `AbstractUser` and this app uses neither — a name here
    is one free-form `display_name`, matching atproto's `displayName` — so two
    empty boxes sat above it inviting an operator to fill in the pair nothing
    reads. Written out rather than filtered out of Django's tuple, because four
    groups on the page are easier to check against the page than a
    comprehension that removes two names from a structure you then have to go
    and look up.

    The cost, since it is a copy: a field Django adds to `AbstractUser` in some
    future release will not appear here until this tuple is updated. That is
    the trade — an admin form that shows exactly what this app stores, against
    one that inherits whatever upstream adds.
    """

    list_display = (
        "username",
        "display_name",
        "did",
        "email",
        "pds_url",
        "last_seen",
        "is_staff",
    )
    search_fields = ("username", "did", "display_name")

    # `email_confirmed` is shown but not editable: it means "the member's PDS
    # vouched for this address", which is not something an operator can decide
    # here. It is worth showing because it answers "why is `email_verified`
    # false in the id_token" without a shell. Corliss clears it itself when the
    # member edits their email at `/account/`.
    # `username` holds the atproto handle, refreshed from the PDS at every
    # login — an edit here survives until then and no longer.
    readonly_fields = (
        "did",
        "email_confirmed",
        "last_seen",
        "last_login",
        "date_joined",
    )

    fieldsets = (
        ("Profile", {"fields": ("display_name", "email", "email_confirmed")}),
        ("ATProto identity", {"fields": ("did", "pds_url")}),
        ("Important dates", {"fields": ("date_joined", "last_login", "last_seen")}),
        (
            "Permissions",
            {
                "fields": (
                    "password",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
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


@admin.register(OidcSession)
class OidcSessionAdmin(admin.ModelAdmin):
    """Which relying parties Corliss believes are holding a session.

    Worth a page because of what a *lingering* row means. A row is deleted the
    moment its relying party accepts a logout token, so anything still here
    after a sign-out or a revocation is a session Corliss tried and failed to
    end — the RP was unreachable, or it rejected the token. That is the state
    an operator wants to find when "revoking someone didn't kick them out of
    chat" gets reported.

    Read-only like `MembershipCache`, but **delete is allowed**, and the
    difference is real rather than an inconsistency. Deleting a cache row would
    discard a membership fact the registry owns. Deleting one of these discards
    only Corliss's belief that somebody is signed in somewhere — which goes
    stale on its own (a rebuilt relying party has no such session), and whose
    only cost is a pointless POST on every future logout. Note it forgets the
    problem rather than fixing it: the session, if it really is live, then runs
    to the relying party's own token expiry.
    """

    list_display = ("user", "client_id", "created_at", "last_authorized_at")
    list_filter = ("client_id",)
    search_fields = ("user__did", "user__username", "sid")
    ordering = ("-last_authorized_at",)
    readonly_fields = ("user", "client_id", "sid", "created_at", "last_authorized_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
