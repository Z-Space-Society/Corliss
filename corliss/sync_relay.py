"""Members' and groups' notes workspaces, which live on scn-notes.

Two words cross here and mean different things on each side. The relay's
**workspace** is the notes: a member's Private workspace, or the shared one a
group of members has. Corliss's `Workspace` model is that **group**: the
members who share one. So the relay names a group by `group_id`, which is a
Corliss `Workspace`'s pk, and in this module a `group` argument is a
`Workspace` row.

The relay holds members' notes and the record of who holds which workspace: a
member, for their one Private workspace, or a group. Corliss holds none of it.
This module asks the relay for a member's Private workspace, which the relay
makes the first time anyone asks, and for a group's workspace under the
group's name, which the relay makes the first time Corliss asks and renames
whenever the name it is sent differs. It is the only place the relay's service
token is used.

Which groups a member is in reaches the relay another way: as the `workspaces`
claim of the tokens `oidc.mint_access_token` issues. The relay keeps no
roster, so nothing here tells it about a member joining or leaving.

`corliss.health` also talks to the relay, to ask whether it is up. That is a
different relationship and stays there: a liveness probe carries no credential
and knows nothing about workspaces.

Three properties hold here, each with a plausible wrong answer:

- **The address is the relay's internal one**, `SYNC_RELAY_URL`, never the
  public notes URL members paste into Obsidian. The relay's proxy does not
  route `/internal/` at all, and the service token has no business crossing
  the edge to reach a neighbour.
- **The caller says whose workspaces, and it is always the signed-in member.**
  The service token can list and create for any DID, so nothing in a request
  may choose one. `views.notes` passes `request.user.did` and nothing else.
  A group's workspace is asked about only after `views._workspace_for_member`
  has found the signed-in member in that group, so the ID in a URL chooses
  nothing either. `all_workspaces` names nobody: it asks for every workspace
  at once, and only `views.systems_notes`, behind `@admin_required`, calls it.
- **Nothing is retried and nothing is stored.** A failure is shown to the
  member, and the next page load asks again. A workspace exists when the relay
  says so and in no table of ours.
"""

import logging

import requests
from django.conf import settings
from django.utils.dateparse import parse_datetime

log = logging.getLogger(__name__)

# Sits on a member's request for a page, like `litellm.LITELLM_TIMEOUT`.
SYNC_RELAY_TIMEOUT = 5

# The relay's own limit on a workspace's name. Checked here first so that a
# name it would refuse never costs a round trip, and compared after trimming,
# as it does.
NAME_MAX = 100


class SyncRelayError(Exception):
    """The relay could not be reached, refused us, or answered unusably."""


def workspace_name_for(group):
    """The name a group's workspace carries: the group's, cut to fit.

    A group's name may be longer than the relay allows a workspace's, and
    refusing to make the workspace over that would be a strange thing to tell
    somebody.
    """
    return group.name.strip()[:NAME_MAX]


def is_configured() -> bool:
    return bool(settings.SYNC_RELAY_URL and settings.SYNC_RELAY_SERVICE_TOKEN)


def _call(method, path="/internal/workspaces", **kwargs):
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


def _workspace(raw):
    """One workspace as the page shows it, from the relay's JSON object."""
    if not isinstance(raw, dict):
        raise SyncRelayError("a workspace in the answer is not the expected shape")
    name = raw.get("name")
    if name is not None and not isinstance(name, str):
        raise SyncRelayError("a workspace in the answer is not the expected shape")

    def when(key):
        value = raw.get(key)
        return parse_datetime(value) if isinstance(value, str) else None

    group_id = raw.get("group_id")
    return {
        # The group's name for its workspace. None for a member's Private
        # workspace, which has none of its own.
        "name": name,
        "url": raw.get("url", ""),
        # The group's ID as a string, or None for a member's Private workspace.
        "group_id": group_id if isinstance(group_id, str) else None,
        # The relay's path for it: "Private", or "Workspaces/Garden Club".
        # Shown as given, never built here.
        "path": raw["path"] if isinstance(raw.get("path"), str) else "",
        "created_at": when("created_at"),
        # Null from the relay until something has been written to it.
        "last_change_at": when("last_change_at"),
        # Null until the relay has walked the workspace since it started.
        # `bytes` is stored Automerge history, not the notes as files.
        "note_count": _count(raw.get("note_count")),
        "bytes": _count(raw.get("bytes")),
    }


def _json(response):
    try:
        return response.json()
    except ValueError as exc:
        raise SyncRelayError("the answer was not JSON") from exc


def list_workspaces(did, groups=()):
    """`did`'s Private workspace, plus the workspaces of the `groups` IDs
    named, oldest first. The relay makes the Private workspace if this is the
    first time anyone has asked for it. Raises `SyncRelayError`.
    """
    params = {"did": did}
    if groups:
        params["groups"] = ",".join(str(g) for g in groups)
    response = _call("GET", params=params)
    if response.status_code != 200:
        log.warning("sync relay: listing workspaces answered %s", response.status_code)
        raise SyncRelayError(f"HTTP {response.status_code}")
    body = _json(response)
    if not isinstance(body, dict) or not isinstance(body.get("workspaces"), list):
        raise SyncRelayError("the answer was not a workspace listing")
    return [_workspace(raw) for raw in body["workspaces"]]


def private_workspace(did):
    """`did`'s Private workspace, made by the relay if this is the first time
    anyone has asked for it. Raises `SyncRelayError`.

    Asks with no groups, so the listing holds only the member's own.
    """
    for found in list_workspaces(did):
        if found["group_id"] is None:
            return found
    raise SyncRelayError("the listing held no Private workspace")


def group_workspace(did, group):
    """The group's workspace, carrying the group's current name. Raises
    `SyncRelayError`.

    The relay makes it if the group has none, and renames it if the name sent
    differs from the one it carries, so this one call serves the group's page
    and its rename. `did` is the signed-in member, whom the caller has already
    found in the group: the relay records them as its maker if it makes it now.
    """
    response = _call(
        "PUT",
        json={
            "did": did,
            "group_id": str(group.pk),
            "name": workspace_name_for(group),
        },
    )
    if response.status_code != 200:
        log.warning(
            "sync relay: asking for a group's workspace answered %s",
            response.status_code,
        )
        raise SyncRelayError(f"HTTP {response.status_code}")
    return _workspace(_json(response))


def all_workspaces():
    """Every workspace on the relay, and each member's documents no workspace
    reaches, as `(workspaces, unfiled)`. Raises `SyncRelayError`.

    For the admin view only. Each workspace is as `list_workspaces` gives it,
    plus `owner_did`: the member who made it, which for a group's workspace is
    not who holds it. `unfiled` is a list of `{did, docs, bytes}`, or None
    while the relay is still indexing after a start, when it cannot tell an
    unfiled note from one in a workspace it has not walked yet.
    """
    response = _call("GET", path="/internal/workspaces/all")
    if response.status_code != 200:
        log.warning(
            "sync relay: listing every workspace answered %s", response.status_code
        )
        raise SyncRelayError(f"HTTP {response.status_code}")
    body = _json(response)
    if not isinstance(body, dict) or not isinstance(body.get("workspaces"), list):
        raise SyncRelayError("the answer was not a workspace listing")

    workspaces = []
    for raw in body["workspaces"]:
        found = _workspace(raw)
        owner = raw.get("owner_did")
        if not isinstance(owner, str):
            raise SyncRelayError("a workspace in the answer names no owner")
        found["owner_did"] = owner
        workspaces.append(found)

    raw_unfiled = body.get("unfiled")
    if raw_unfiled is None:
        return workspaces, None
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
    return workspaces, unfiled
