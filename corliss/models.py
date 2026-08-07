"""Corliss's data model — deliberately small, all in one module.

Three models: the DID-keyed `User` everything references, the server-side
atproto token store, and the OIDC provider's short-lived auth codes. The
import contract is `from corliss.models import ...`; if this file ever grows
unwieldy it can become a `models/` package re-exporting the same names
without touching callers or the database.
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


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
