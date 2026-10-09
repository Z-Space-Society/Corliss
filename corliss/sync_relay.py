"""A member's vaults, which live on scn-sync-relay.

The relay holds members' notes and the record of who owns which vault. Corliss
holds none of it. This module asks the relay two things on a member's behalf,
what vaults they have and to make them a new one, and is the only place the
relay's service token is used.

`corliss.health` also talks to the relay, to ask whether it is up. That is a
different relationship and stays there: a liveness probe carries no credential
and knows nothing about vaults.

Three properties hold here, each with a plausible wrong answer:

- **The address is the relay's internal one**, `SYNC_RELAY_URL`, never the
  public sync URL members paste into Obsidian. The relay's proxy does not
  route `/internal/` at all, and the service token has no business crossing
  the edge to reach a neighbour.
- **The caller says whose vaults, and it is always the signed-in member.**
  The service token can list and create for any DID, so nothing in a request
  may choose one. `views.vaults` passes `request.user.did` and nothing else.
- **Nothing is retried and nothing is stored.** A failure is shown to the
  member, who can press the button again. A vault exists when the relay says
  so and in no table of ours.
"""

import logging

import requests
from django.conf import settings
from django.utils.dateparse import parse_datetime

log = logging.getLogger(__name__)

# Sits on a member's request for a page, like `litellm.LITELLM_TIMEOUT`.
SYNC_RELAY_TIMEOUT = 5

# The relay's own limit. Checked here first so that a name it would refuse
# never costs a round trip, and compared after trimming, as it does.
VAULT_NAME_MAX = 100


class SyncRelayError(Exception):
    """The relay could not be reached, refused us, or answered unusably."""


class NameTaken(SyncRelayError):
    """The member already has a vault with that name, whatever its case."""


def is_configured() -> bool:
    return bool(settings.SYNC_RELAY_URL and settings.SYNC_RELAY_SERVICE_TOKEN)


def _call(method, **kwargs):
    url = settings.SYNC_RELAY_URL.rstrip("/") + "/internal/vaults"
    try:
        return requests.request(
            method,
            url,
            headers={"Authorization": f"Bearer {settings.SYNC_RELAY_SERVICE_TOKEN}"},
            timeout=SYNC_RELAY_TIMEOUT,
            # The relay never redirects these. If something in between does,
            # following it would carry the service token somewhere else.
            allow_redirects=False,
            **kwargs,
        )
    except requests.RequestException as exc:
        log.warning("sync relay: %s /internal/vaults failed: %s", method, exc)
        raise SyncRelayError("unreachable") from exc


def _vault(raw):
    """One vault as the page shows it, from the relay's JSON object."""
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        raise SyncRelayError("a vault in the answer is not the expected shape")

    def when(key):
        value = raw.get(key)
        return parse_datetime(value) if isinstance(value, str) else None

    return {
        "name": raw["name"],
        "url": raw.get("url", ""),
        "created_at": when("created_at"),
        # Null from the relay until something has been written to the vault.
        "last_change_at": when("last_change_at"),
    }


def _json(response):
    try:
        return response.json()
    except ValueError as exc:
        raise SyncRelayError("the answer was not JSON") from exc


def list_vaults(did):
    """The vaults `did` owns, oldest first. Raises `SyncRelayError`."""
    response = _call("GET", params={"did": did})
    if response.status_code != 200:
        log.warning("sync relay: listing vaults answered %s", response.status_code)
        raise SyncRelayError(f"HTTP {response.status_code}")
    body = _json(response)
    if not isinstance(body, dict) or not isinstance(body.get("vaults"), list):
        raise SyncRelayError("the answer was not a vault listing")
    return [_vault(raw) for raw in body["vaults"]]


def create_vault(did, name):
    """Create a vault owned by `did`. Raises `NameTaken` or `SyncRelayError`."""
    response = _call("POST", json={"did": did, "name": name})
    if response.status_code == 409:
        raise NameTaken(name)
    if response.status_code != 201:
        log.warning("sync relay: creating a vault answered %s", response.status_code)
        raise SyncRelayError(f"HTTP {response.status_code}")
    return _vault(_json(response))
