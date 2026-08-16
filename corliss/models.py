"""Corliss's data model — deliberately small, all in one module.

Four models: the DID-keyed `User` everything references, the server-side
atproto token store, the OIDC provider's short-lived auth codes, and the
membership cache. The import contract is `from corliss.models import ...`; if
this file ever grows unwieldy it can become a `models/` package re-exporting
the same names without touching callers or the database.
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property


class User(AbstractUser):
    """A Corliss member, authenticated via ATProto OAuth.

    `did` is the stable identifier we trust and key on — it never changes, so
    everything downstream (sessions, OIDC `sub`) references it. `username` holds
    the handle for display only; it's mutable and gets refreshed on each login
    (handles can change; DIDs cannot). Password auth is unused — login is via
    ATProto.

    `email` is sourced from the member's PDS on each login (the
    `transition:email` scope + `com.atproto.server.getSession`, see
    `corliss.atproto.fetch_session_email`) — it is best-effort and may be
    blank if the member declined the scope or has none on file. It must still
    not be relied on as an identifier: DID is the only stable key.
    """

    # Stable atproto identifier — the thing everything actually references.
    did = models.CharField(
        max_length=255,
        unique=True,
        editable=False,
        help_text="Permanent atproto DID, e.g. did:plc:ewvi7nxzyoun6zhxrhs64oiz",
    )

    # Current PDS, resolved from the DID document. Needed for token refresh.
    pds_url = models.URLField(blank=True)

    # Whether the PDS reported this email as confirmed (`emailConfirmed` from
    # getSession). `email` itself is inherited from AbstractUser.
    email_confirmed = models.BooleanField(default=False)

    last_seen = models.DateTimeField(null=True, blank=True)

    @cached_property
    def is_cluster_admin(self):
        """ELEVATE, as an attribute — usable as `user.is_cluster_admin` in any
        template, the way `is_superuser` is.

        Read, never stored: this is a property over the roster in the service
        DID's repo, not a database flag. That distinction is the whole point of
        `corliss.membership`'s roster section — a stored flag would drift from
        the record and could not be revoked by editing it.

        `cached_property` so the nav asking on every render costs one lookup per
        request rather than one per mention. `membership` itself imports this
        module, so the import is local to the call.
        """
        from corliss import membership

        return membership.is_cluster_admin(self.did)

    @cached_property
    def has_pending_application(self):
        """Has this member asked for membership and not yet been answered?

        PLACEHOLDER — always False. An application will be a record in the
        member's own PDS that the registry picks up; none of that exists yet, so
        there is nothing to read. Isolated here so that when it does exist this
        is the only place that changes, rather than the nav template.
        """
        return False

    @cached_property
    def membership_label(self):
        """This member's standing, for display: "none", "pending" or a tier.

        Reads `active` before `tier`, which `MembershipCache` requires: a
        revoked row keeps its last tier for audit, so tier alone would show an
        entitlement that has already ended.
        """
        from corliss import membership

        row = membership.membership_for(self)
        if row is not None and row.active:
            # Tier slugs are SCN-owned and shaped level-0 … level-9. Rendered
            # rather than mapped, so a tier added upstream shows up here without
            # a code change — the same reason the push does not validate them.
            return row.tier.replace("-", " ") if row.tier else "member"
        if self.has_pending_application:
            return "pending"
        return "none"

    def touch_last_seen(self, *, save=True):
        """Stamp the current time as this member's last activity."""
        self.last_seen = timezone.now()
        if save:
            self.save(update_fields=["last_seen"])

    def __str__(self):
        return self.username or self.did


class AtprotoToken(models.Model):
    """Server-side storage of a member's atproto OAuth tokens + DPoP key.

    Held server-side (never sent to the browser) so the session cookie stays the
    only client-side credential. The `dpop_private_pem` is the *per-session*
    ephemeral DPoP key the tokens are bound to — needed to make authenticated PDS
    calls and to refresh.

    NOTE: stored as-is here; encryption-at-rest is a deployment decision.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="atproto_token",
    )
    pds_url = models.URLField()
    issuer = models.URLField()
    token_endpoint = models.URLField()

    access_token = models.TextField()
    refresh_token = models.TextField(blank=True)
    dpop_private_pem = models.TextField()
    dpop_nonce = models.CharField(max_length=512, blank=True)

    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AtprotoToken({self.user})"


class OidcAuthCode(models.Model):
    """A short-lived OIDC authorization code issued to the relying party.

    Bound to the member, the requesting client, the redirect URI, and the
    `nonce` so the token endpoint can validate the exchange and echo the nonce
    into the `id_token`. Single-use: marked `used` once redeemed.
    """

    code = models.CharField(max_length=128, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    client_id = models.CharField(max_length=255)
    redirect_uri = models.URLField()
    nonce = models.CharField(max_length=255, blank=True)
    scope = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def is_valid(self) -> bool:
        return not self.used and timezone.now() < self.expires_at

    def __str__(self):
        return f"OidcAuthCode({self.user}, used={self.used})"


class MembershipCache(models.Model):
    """Who the registry says is a member, and at what tier. **A cache.**

    Named for what it is so no future reader mistakes it for a source of
    truth. The Shared Computer Network registry — grant and revocation records
    in a HappyView space — is authoritative. Membership there is *derived*:
    append-only events resolved latest-event-wins, never a stored boolean. So
    this table holds a cached computation, not a second copy of a fact, and it
    must stay rebuildable from the registry alone.

    Two rules follow, and they are the whole contract:

    - **Never write here except from a registry event.** No admin action, no
      login side effect, no "just mark them active" repair. If this table and
      the registry disagree, this table is wrong by definition.
    - **Never read `tier` without checking `active`.** A revoked member keeps
      their last tier here for audit ("what were they on when it ended?"), so
      `tier` alone reads as an entitlement that no longer exists.

    Rows arrive by push: the registry POSTs each grant/revoke to Corliss (see
    `corliss.membership`). Push is best-effort and can be missed or reordered,
    which is why `last_rkey` exists — its TID orders events and makes a
    replayed or stale push a no-op rather than a resurrection.

    Keyed by DID rather than a FK to `User` on purpose. A grant can be written
    for someone who has never logged in — that is how INVITE works, an admin
    grants preemptively and the person is already a member when they arrive.
    A FK would force a `User` row at push time, which would mean a bearer
    token could mint users (today every `User` implies a completed atproto
    token exchange) and would make rebuilding this cache mutate the user
    table. `membership_for` bridges the two when a caller has a `User`.
    """

    did = models.CharField(max_length=255, unique=True, db_index=True)

    active = models.BooleanField(
        help_text="Resolved membership: true after a grant, false after a revocation.",
    )

    tier = models.CharField(
        max_length=64,
        blank=True,
        help_text=(
            "SCN-owned tier slug (level-0 … level-9) from the most recent grant. "
            "Retained after revocation for audit — always check `active` too."
        ),
    )

    # The registry rkey of the event this row reflects: `{memberDid}:{tid}`.
    # The TID orders events across BOTH collections, since one runtime issues
    # them — which is what lets a single field order grants against
    # revocations.
    last_rkey = models.CharField(max_length=600)

    # `grantedAt` or `revokedAt` from the record. Second-resolution, and
    # therefore NOT the ordering key — see `corliss.membership.tid_of`.
    last_event_at = models.DateTimeField()

    # The admin who authored the event, for audit: "who let this person in?"
    # answerable without a registry round-trip. Asserted by the push and not
    # yet verified against the roster — see `corliss.membership`.
    author_did = models.CharField(max_length=255)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "membership cache entries"

    def __str__(self):
        state = f"active {self.tier}" if self.active else "revoked"
        return f"MembershipCache({self.did}, {state})"
