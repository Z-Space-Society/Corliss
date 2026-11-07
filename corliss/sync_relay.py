"""Members' and workspaces' vaults, which live on scn-sync-relay.

The relay holds members' notes and the record of who holds which vault: a
member, for their one private vault, or a workspace. Corliss holds none of it.
This module asks the relay for a member's private vault, which the relay makes
the first time anyone asks, and for a workspace's vault under the workspace's
name, which the relay makes the first time Corliss asks and renames whenever
the name it is sent differs. It is the only place the relay's service token is
used.

Which workspaces a member is in reaches the relay two ways. The `workspaces`
claim of the tokens `oidc.mint_access_token` issues is the first, and the one
access rests on. The second is each workspace's roster, pushed here by the
receivers in `corliss.signals` whenever it changes, with every member's handle
and name. The relay keeps the roster as a second check that must agree with
the token, so a removal takes effect at once rather than when the member's
token expires, and the names are what it shows beside notes and edits.

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
  may choose one. `views.notes` passes `request.user.did` and nothing else.
  A workspace's vault is asked about only after `views._workspace_for_member`
  has found the signed-in member in that workspace, so the workspace ID in a
  URL chooses nothing either. `all_vaults` names nobody: it asks for every
  vault at once, and only `views.systems_notes`, behind `@admin_required`,
  calls it.
- **Nothing is retried and nothing is stored.** A failure is shown to the
  member, and the next page load asks again. A vault exists when the relay
  says so and in no table of ours. A push that fails is logged and repaired
  by `manage.py sync_relay_rosters`, which sends everything again.
- **A roster push is the whole roster, read after the change commits.** Never
  a delta: two pushes that land out of order, or one that is lost, leave the
  relay with an answer the next push replaces outright.
"""

import logging

import requests
from django.conf import settings
from django.utils.dateparse import parse_datetime

from corliss.models import User

log = logging.getLogger(__name__)

# Sits on a member's request for a page, like `litellm.LITELLM_TIMEOUT`.
SYNC_RELAY_TIMEOUT = 5

# The relay's own limit. Checked here first so that a name it would refuse
# never costs a round trip, and compared after trimming, as it does.
VAULT_NAME_MAX = 100


class SyncRelayError(Exception):
    """The relay could not be reached, refused us, or answered unusably."""


def vault_name_for(workspace):
    """The name a workspace's vault carries: the workspace's, cut to fit.

    A workspace's name may be longer than the relay allows a vault's, and
    refusing to make the vault over that would be a strange thing to tell
    somebody.
    """
    return workspace.name.strip()[:VAULT_NAME_MAX]


def is_configured() -> bool:
    return bool(settings.SYNC_RELAY_URL and settings.SYNC_RELAY_SERVICE_TOKEN)


def _call(method, path="/internal/vaults", **kwargs):
    url = settings.SYNC_RELAY_URL.rstrip("/") + path
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
        log.warning("sync relay: %s %s failed: %s", method, path, exc)
        raise SyncRelayError("unreachable") from exc


def _count(value):
    """An integer the relay sent, or None for anything else."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _vault(raw):
    """One vault as the page shows it, from the relay's JSON object."""
    if not isinstance(raw, dict):
        raise SyncRelayError("a vault in the answer is not the expected shape")
    name = raw.get("name")
    if name is not None and not isinstance(name, str):
        raise SyncRelayError("a vault in the answer is not the expected shape")

    def when(key):
        value = raw.get(key)
        return parse_datetime(value) if isinstance(value, str) else None

    workspace = raw.get("workspace")
    return {
        # The workspace's name for its vault. None for a member's private
        # vault, which has none of its own from relay v0.5.0.
        "name": name,
        "url": raw.get("url", ""),
        # The workspace's ID as a string, or None for a member's private vault.
        "workspace": workspace if isinstance(workspace, str) else None,
        # The relay's path for it: "Private", or "Workspaces/Garden Club".
        # Shown as given, never built here; blank from a relay before v0.4.2.
        "path": raw["path"] if isinstance(raw.get("path"), str) else "",
        "created_at": when("created_at"),
        # Null from the relay until something has been written to the vault.
        "last_change_at": when("last_change_at"),
        # Null until the relay has walked the vault since it started, and
        # absent from a relay older than v0.3.0. `bytes` is stored Automerge
        # history, not the notes as files.
        "note_count": _count(raw.get("note_count")),
        "bytes": _count(raw.get("bytes")),
    }


def _json(response):
    try:
        return response.json()
    except ValueError as exc:
        raise SyncRelayError("the answer was not JSON") from exc


def list_vaults(did, workspaces=()):
    """`did`'s private vault, plus the vaults of the `workspaces` IDs named,
    oldest first. The relay makes the private vault if this is the first time
    anyone has asked for it. Raises `SyncRelayError`.
    """
    params = {"did": did}
    if workspaces:
        params["workspaces"] = ",".join(str(w) for w in workspaces)
    response = _call("GET", params=params)
    if response.status_code != 200:
        log.warning("sync relay: listing vaults answered %s", response.status_code)
        raise SyncRelayError(f"HTTP {response.status_code}")
    body = _json(response)
    if not isinstance(body, dict) or not isinstance(body.get("vaults"), list):
        raise SyncRelayError("the answer was not a vault listing")
    return [_vault(raw) for raw in body["vaults"]]


def private_vault(did):
    """`did`'s private vault, made by the relay if this is the first time
    anyone has asked for it. Raises `SyncRelayError`.

    Asks with no workspaces, so the listing holds only the member's own.
    """
    for found in list_vaults(did):
        if found["workspace"] is None:
            return found
    raise SyncRelayError("the listing held no private vault")


def workspace_vault(did, workspace):
    """The workspace's vault, carrying the workspace's current name. Raises
    `SyncRelayError`.

    The relay makes it if the workspace has none, and renames it if the name
    sent differs from the one it carries, so this one call serves the
    workspace's page and its rename. `did` is the signed-in member, whom the
    caller has already found in the workspace: the relay records them as its
    maker if it makes it now.
    """
    response = _call(
        "PUT",
        path="/internal/vaults/workspace",
        json={
            "did": did,
            "workspace": str(workspace.pk),
            "name": vault_name_for(workspace),
        },
    )
    if response.status_code != 200:
        log.warning(
            "sync relay: asking for a workspace vault answered %s",
            response.status_code,
        )
        raise SyncRelayError(f"HTTP {response.status_code}")
    return _vault(_json(response))


def all_vaults():
    """Every vault on the relay, and each member's documents no vault reaches,
    as `(vaults, unfiled)`. Raises `SyncRelayError`.

    For the admin view only. Each vault is as `list_vaults` gives it, plus
    `owner_did`: the member who made it, which for a workspace's vault is not
    who holds it. `unfiled` is a list of `{did, docs, bytes}`, or None while
    the relay is still indexing after a start, when it cannot tell an
    unfiled note from one in a vault it has not walked yet.
    """
    response = _call("GET", path="/internal/vaults/all")
    if response.status_code != 200:
        log.warning("sync relay: listing every vault answered %s", response.status_code)
        raise SyncRelayError(f"HTTP {response.status_code}")
    body = _json(response)
    if not isinstance(body, dict) or not isinstance(body.get("vaults"), list):
        raise SyncRelayError("the answer was not a vault listing")

    vaults = []
    for raw in body["vaults"]:
        found = _vault(raw)
        owner = raw.get("owner_did")
        if not isinstance(owner, str):
            raise SyncRelayError("a vault in the answer names no owner")
        found["owner_did"] = owner
        vaults.append(found)

    raw_unfiled = body.get("unfiled")
    if raw_unfiled is None:
        return vaults, None
    if not isinstance(raw_unfiled, list):
        raise SyncRelayError("unfiled is not a list")
    unfiled = []
    for entry in raw_unfiled:
        if not isinstance(entry, dict) or not isinstance(entry.get("did"), str):
            raise SyncRelayError("an unfiled entry is not the expected shape")
        unfiled.append(
            {
                "did": entry["did"],
                "docs": _count(entry.get("docs")) or 0,
                "bytes": _count(entry.get("bytes")) or 0,
            }
        )
    return vaults, unfiled


def _pushed(response, what):
    if response.status_code not in (200, 204):
        log.warning("sync relay: pushing %s answered %s", what, response.status_code)
        raise SyncRelayError(f"HTTP {response.status_code}")


def push_workspace_members(workspace_pk):
    """Send the relay the workspace's whole roster, as DIDs, read now. A
    workspace that no longer exists, or has nobody in it, sends an empty list,
    which closes its vault to everyone. Raises `SyncRelayError`.
    """
    dids = list(
        User.objects.filter(workspaces__pk=workspace_pk)
        .order_by("did")
        .values_list("did", flat=True)
    )
    _pushed(
        _call(
            "PUT",
            path=f"/internal/workspaces/{workspace_pk}/members",
            json={"members": dids},
        ),
        f"workspace {workspace_pk}'s roster",
    )


def push_member(did, handle, name):
    """Send the relay a member's handle and name, for showing beside their
    notes and edits. `name` is blank when they have none. Raises
    `SyncRelayError`.
    """
    _pushed(
        _call(
            "PUT",
            path=f"/internal/members/{did}",
            json={"handle": handle, "name": name},
        ),
        "a member's name",
    )
