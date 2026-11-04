"""Members' and workspaces' vaults, which live on scn-sync-relay.

The relay holds members' notes and the record of who holds which vault: a
member, for a private vault, or a workspace. Corliss holds none of it. This
module asks the relay what vaults a member or a workspace has, to make one, and
to rename a workspace's when the workspace is renamed. It is the only place the
relay's service token is used.

Which workspaces a member is in reaches the relay another way: as the
`workspaces` claim of the tokens `oidc.mint_access_token` issues. The relay
keeps no roster, so nothing here tells it about a member joining or leaving.

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


class WorkspaceHasVault(SyncRelayError):
    """The workspace already has its vault. A workspace has one."""


def vault_name_for(workspace):
    """The name a workspace's vault carries: the workspace's, cut to fit.

    A workspace's name may be longer than the relay allows a vault's, and
    refusing to make the vault over that would be a strange thing to tell
    somebody. Cut the same way at create and at rename, so the two agree.
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
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        raise SyncRelayError("a vault in the answer is not the expected shape")

    def when(key):
        value = raw.get(key)
        return parse_datetime(value) if isinstance(value, str) else None

    workspace = raw.get("workspace")
    return {
        "name": raw["name"],
        "url": raw.get("url", ""),
        # The workspace's ID as a string, or None for a member's private vault.
        "workspace": workspace if isinstance(workspace, str) else None,
        # The relay's name for it under its group, "Workspaces/Garden Club".
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
    """The private vaults `did` holds, oldest first, plus the vaults of the
    `workspaces` IDs named. Raises `SyncRelayError`.

    The Notes page names no workspaces: it is about private vaults only.
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


def create_vault(did, name):
    """Create a vault owned by `did`. Raises `NameTaken` or `SyncRelayError`."""
    response = _call("POST", json={"did": did, "name": name})
    if response.status_code == 409:
        raise NameTaken(name)
    if response.status_code != 201:
        log.warning("sync relay: creating a vault answered %s", response.status_code)
        raise SyncRelayError(f"HTTP {response.status_code}")
    return _vault(_json(response))


def workspace_vault(did, workspace):
    """The workspace's vault, or None if it has none yet. Raises
    `SyncRelayError`.

    `did` is the signed-in member, who the caller has already found in the
    workspace. The relay's listing needs a DID, and gives back their private
    vaults too, which are dropped here.
    """
    wanted = str(workspace.pk)
    for found in list_vaults(did, workspaces=[wanted]):
        if found["workspace"] == wanted:
            return found
    return None


def create_workspace_vault(did, workspace):
    """Make the workspace's vault, named after it. `did` is the member making
    it. Raises `WorkspaceHasVault` or `SyncRelayError`."""
    response = _call(
        "POST",
        json={
            "did": did,
            "name": vault_name_for(workspace),
            "workspace": str(workspace.pk),
        },
    )
    if response.status_code == 409:
        raise WorkspaceHasVault(workspace.pk)
    if response.status_code != 201:
        log.warning(
            "sync relay: creating a workspace vault answered %s", response.status_code
        )
        raise SyncRelayError(f"HTTP {response.status_code}")
    return _vault(_json(response))


def rename_workspace_vault(workspace):
    """Give the workspace's vault the workspace's current name. Raises
    `SyncRelayError`.

    A workspace with no vault is not an error: there is nothing to rename. That
    is a `404` saying `no_vault`, and only that: any other 404 is a relay that
    is not the one we think, and is reported.
    """
    response = _call(
        "PATCH",
        json={"workspace": str(workspace.pk), "name": vault_name_for(workspace)},
    )
    if response.status_code == 204:
        return
    if response.status_code == 404:
        body = _json(response)
        if isinstance(body, dict) and body.get("error") == "no_vault":
            return
    log.warning(
        "sync relay: renaming a workspace vault answered %s", response.status_code
    )
    raise SyncRelayError(f"HTTP {response.status_code}")


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
