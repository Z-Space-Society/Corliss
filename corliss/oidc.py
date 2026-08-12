"""OIDC *provider* core: discovery document, auth-code issuance, id_token minting.

This is the half of Corliss that re-exposes a logged-in member to relying
parties. The `id_token` is RS256 (broad OIDC-client compatibility), signed with
the OIDC key from `corliss.signing` and verifiable via the JWKS endpoint.
Claims: `sub` = DID, `handle`, and `email`/`email_verified` when the member's
PDS supplied one (see `corliss.atproto.fetch_session_email`).
"""

import secrets
import time
from datetime import timedelta

from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from corliss import signing
from corliss.models import OidcAuthCode

CODE_TTL_SECONDS = 600
ID_TOKEN_TTL_SECONDS = 3600


def base_url() -> str:
    return settings.PUBLIC_BASE_URL.rstrip("/")


def discovery_document() -> dict:
    return {
        "issuer": base_url(),
        "authorization_endpoint": base_url() + reverse("authorize"),
        "token_endpoint": base_url() + reverse("token"),
        "jwks_uri": base_url() + reverse("jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": [
            "sub",
            "handle",
            "preferred_username",
            "email",
            "email_verified",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
        ],
    }


def issue_code(user, *, client_id, redirect_uri, nonce="", scope="") -> str:
    code = secrets.token_urlsafe(48)
    OidcAuthCode.objects.create(
        code=code,
        user=user,
        client_id=client_id,
        redirect_uri=redirect_uri,
        nonce=nonce,
        scope=scope,
        expires_at=timezone.now() + timedelta(seconds=CODE_TTL_SECONDS),
    )
    return code


def mint_id_token(user, *, client_id, nonce="") -> str:
    now = int(time.time())
    payload = {
        "iss": base_url(),
        "sub": user.did,  # DID is the stable subject identifier
        "aud": client_id,
        "iat": now,
        "exp": now + ID_TOKEN_TTL_SECONDS,
        "auth_time": now,
        "handle": user.username,
        "preferred_username": user.username,
    }
    # Best-effort claim: only present when the member's PDS supplied an email
    # (fetch_session_email at login). Absent, not empty-string, when unknown.
    if user.email:
        payload["email"] = user.email
        payload["email_verified"] = user.email_confirmed
    if nonce:
        payload["nonce"] = nonce  # OIDC requires echoing the RP's nonce
    return signing.sign_rs256(payload)
