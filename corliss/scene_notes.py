"""Scene notes — the record layer, and the only place that knows the shape.

A scene note is one record, `network.sharedcomputer.notes`. The draft lexicon
is in `lexicons/network/sharedcomputer/notes.json`; the design argument is in
the SCN vault under `Code/Scene Note Lexicon.md`.

**Prototype scope, deliberately small.** One author — the signed-in member —
writing **public records into their own repo**. No spaces, no CRDT, no shared
workspace: those are steps 2 and 3 of the prototype. What this buys is the
loop worth testing first: write on one device, read on another, with the same
record shape a full implementation will use.

Reads are unauthenticated (`com.atproto.repo.listRecords` is public), so a note
written here and a note written by any other atproto client read the same way.
Writes go through `atproto.write_record`, which acts as the member.

Kept out on purpose: `automerge`, `heads`, `docId`, `blobs`, `scene`. They are
optional in the lexicon, and a text-only record is valid — step 3 fills them
in.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone

import requests

from corliss import atproto

COLLECTION = "network.sharedcomputer.notes"

#: markpub's flavour. `ofm` is the ask; until it lands, GFM plus an extension
#: and a renderer name that actually exists.
FLAVOUR = "gfm"
EXTENSIONS = ["obsidian"]
RENDERING_RULES = "obsidian-markdown"

TIMEOUT = 10

#: Base32-sortable, the alphabet TIDs use.
_B32 = "234567abcdefghijklmnopqrstuvwxyz"


class SceneNotesError(Exception):
    """A scene note could not be read or written."""


#: The default workspace. There is no record for it and nothing to join: it is
#: the name for the scene notes that are public in a member's own repo, which is
#: every note this prototype writes. Real workspaces — spaces, with a roster and
#: a credential — come later and will look nothing like this one.
PUBLIC_WORKSPACE = "Public"


def public_summary(did: str) -> dict:
    """Count and last change for the Public workspace, or None-ish if unreachable.

    The workspaces page shows this in the same shape as the relay's rows, so it
    returns `{"count": int | None, "last_change": str | None}` rather than
    raising: a PDS that is down should grey out one row, not break the page.
    """
    try:
        notes = list_notes(did)
    except SceneNotesError:
        return {"count": None, "last_change": None}
    last = notes[0]["updated"] if notes else None
    return {"count": len(notes), "last_change": last}


def new_tid() -> str:
    """A TID: 13 base32-sortable characters, sortable by creation time.

    Microseconds since the epoch in the high 52 bits, a random clock identifier
    in the low 11 — the layout atproto uses for record keys. Only used for
    rkeys and `noteId`s we mint; nothing depends on it parsing back.
    """
    micros = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
    clock = int.from_bytes(os.urandom(2), "big") & 0x7FF
    n = (micros << 11) | clock
    out = []
    for _ in range(13):
        out.append(_B32[n & 31])
        n >>= 5
    return "".join(reversed(out))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_TAGS = re.compile(r"(?:^|\s)#([A-Za-z][\w-]{0,49})")


def slug(title: str) -> str:
    """A filename from a title, never empty."""
    value = _SLUG_STRIP.sub("-", title.lower()).strip("-")
    return value[:80] or "untitled"


def tags_in(markdown: str) -> list[str]:
    """`#tags` in the body, for browsing. A projection, not truth."""
    seen: list[str] = []
    for tag in _TAGS.findall(markdown):
        if tag not in seen:
            seen.append(tag)
    return seen[:32]


def text_hash(markdown: str) -> str:
    return hashlib.sha256(markdown.encode("utf-8")).hexdigest()


_FM_LINE = re.compile(r"^([A-Za-z0-9_.-]+):\s*(.*)$")
_H1 = re.compile(r"^#\s+(.+)$", re.MULTILINE)


def _parse_block(lines: list[str]) -> dict:
    """`key: value`, `key: a, b`, and block lists, out of front-matter lines."""
    properties: dict = {}
    key = None
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")) and key:
            item = line.strip().lstrip("-").strip().strip("'\"")
            if item and isinstance(properties.get(key), list):
                properties[key].append(item)
            continue
        match = _FM_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        properties[key] = value if value else []
    return properties


def split_frontmatter(text: str) -> tuple[dict, str]:
    """(properties, body) — a tolerant YAML front-matter split.

    Hand-rolled rather than a YAML dependency, and deliberately shallow: the
    cases that matter are `key: value`, `key: a, b` and a block list under a
    key. Anything it does not understand is ignored, and a file with no
    front-matter comes back as `({}, text)` — the note is never lost because
    its metadata was odd.

    **It also recovers a block that lost its opening fence.** Pasting from
    somewhere that ate the first line is ordinary, and the shape is
    unmistakable: nothing but `key: value` lines, then `---`. Requiring the
    fence would show that metadata as prose, which is wrong twice — it is not
    what the author wrote, and it buries the title.

    CRLF is normalised first: notes arrive from a Windows clipboard and from a
    textarea alike, and `---\r\n` must split the same as `---\n`.
    """
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")

    if normalised.startswith("---\n"):
        end = normalised.find("\n---", 4)
        if end == -1:
            return {}, text
        body = normalised[end + 4 :]
        return _parse_block(normalised[4:end].split("\n")), body.lstrip("\n")

    # No opening fence: accept a block of `key: value` lines closed by `---`.
    lines = normalised.split("\n")
    for index, line in enumerate(lines[:40]):
        if line.strip() != "---":
            continue
        candidate = lines[:index]
        if not candidate:
            break
        if all(
            not item.strip()
            or _FM_LINE.match(item)
            or item.startswith((" ", "\t"))
            for item in candidate
        ) and any(_FM_LINE.match(item) for item in candidate):
            return _parse_block(candidate), "\n".join(lines[index + 1 :]).lstrip("\n")
        break

    return {}, text


def _as_list(value) -> list[str]:
    """A front-matter list, whether written `a, b` or as a YAML block list."""
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = value.split(",")
    else:
        return []
    return [item.strip().strip("'\"#") for item in items if item.strip().strip("'\"#")]


def display_title(properties: dict, body: str, fallback: str = "") -> str:
    """Front-matter `title`, then the first H1, then whatever the record says."""
    value = properties.get("title")
    if isinstance(value, str) and value.strip():
        return value.strip().strip("'\"")
    match = _H1.search(body)
    if match:
        return match.group(1).strip()
    return fallback or "Untitled"


def tags_of(properties: dict, body: str) -> list[str]:
    """Front-matter tags plus inline `#tags`, deduped, in that order."""
    seen: list[str] = []
    for tag in _as_list(properties.get("tags")) + tags_in(body):
        if tag and tag not in seen:
            seen.append(tag)
    return seen[:32]


def body_of(note: dict) -> str:
    """The markdown out of an `at.markpub.markdown`, defensively.

    A record that is not shape we wrote is not an error — it is someone else's
    record in a collection we read by name — so anything unexpected reads as an
    empty body rather than raising in a template.
    """
    body = note.get("body") or {}
    text = body.get("text") or {}
    markdown = text.get("markdown")
    return markdown if isinstance(markdown, str) else ""


def build_record(*, note_id: str, title: str, markdown: str, created_at: str) -> dict:
    now = _now()
    return {
        "$type": COLLECTION,
        "noteId": note_id,
        "path": f"{slug(title)}.md",
        "title": title,
        "body": {
            "$type": "at.markpub.markdown",
            "flavor": FLAVOUR,
            "extensions": list(EXTENSIONS),
            "renderingRules": RENDERING_RULES,
            "text": {"$type": "at.markpub.text", "markdown": markdown},
        },
        "createdAt": created_at,
        "updatedAt": now,
        "textHash": text_hash(markdown),
        "tags": tags_in(markdown),
        "status": "live",
    }


def _pds_for(did: str) -> str:
    doc = atproto.fetch_did_document(did)
    return atproto.pds_endpoint_from_doc(doc)


def _shape(rkey: str, entry: dict, value: dict) -> dict:
    """One view of a record for templates: title, tags and body already worked out.

    The record's own `title` and `tags` are projections written at save time;
    the note it holds may have front-matter that says something newer, because
    it was pasted in rather than saved through this app. **The body wins**:
    front-matter `title`, then the first H1, then the record. Same for tags.
    """
    raw = body_of(value)
    properties, body = split_frontmatter(raw)
    return {
        "rkey": rkey,
        "uri": entry.get("uri"),
        "cid": entry.get("cid"),
        "title": display_title(properties, body, value.get("title") or ""),
        "markdown": body,
        "raw": raw,
        "properties": properties,
        "tags": tags_of(properties, body) or (value.get("tags") or []),
        "updated": value.get("updatedAt") or value.get("createdAt") or "",
        "created": value.get("createdAt") or "",
        "record": value,
    }


def list_notes(did: str, limit: int = 100) -> list[dict]:
    """The member's scene notes, newest first by `updatedAt`.

    One `listRecords` against their PDS. Sorted here rather than trusted from
    the PDS, because `listRecords` orders by rkey (creation) and a note edited
    today belongs at the top regardless of when it was made.
    """
    try:
        pds_url = _pds_for(did)
    except Exception as exc:  # atproto.OAuthError and anything DNS-shaped
        raise SceneNotesError(f"could not resolve the PDS for {did}") from exc

    try:
        response = requests.get(
            f"{pds_url}/xrpc/com.atproto.repo.listRecords",
            params={"repo": did, "collection": COLLECTION, "limit": limit},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        records = response.json().get("records", [])
    except (requests.RequestException, ValueError) as exc:
        raise SceneNotesError("could not read notes from the PDS") from exc

    notes = []
    for entry in records:
        value = entry.get("value")
        if not isinstance(value, dict):
            continue
        if value.get("status") == "deleted":
            continue
        notes.append(_shape(entry.get("uri", "").rsplit("/", 1)[-1], entry, value))
    notes.sort(key=lambda n: n["updated"], reverse=True)
    return notes


def get_note(did: str, rkey: str) -> dict:
    """One note by rkey, or `SceneNotesError` if it is not there."""
    try:
        value = atproto.find_record(did, COLLECTION, rkey)
    except Exception as exc:
        raise SceneNotesError("could not read that note") from exc
    if value is None:
        raise SceneNotesError("no such note")
    return _shape(rkey, {}, value)


def create_note(user, *, title: str, markdown: str) -> str:
    """Write a new note into the member's repo. Returns its rkey."""
    rkey = new_tid()
    record = build_record(
        note_id=new_tid(), title=title, markdown=markdown, created_at=_now()
    )
    return _write(user, rkey, record)


def update_note(user, rkey: str, *, title: str, markdown: str) -> str:
    """Replace a note's text, keeping its identity and creation time.

    `noteId` and `createdAt` come from the stored record, not from this call:
    identity must not change because someone edited a title.
    """
    existing = get_note(user.did, rkey)["record"]
    record = build_record(
        note_id=existing.get("noteId") or new_tid(),
        title=title,
        markdown=markdown,
        created_at=existing.get("createdAt") or _now(),
    )
    return _write(user, rkey, record)


def _write(user, rkey: str, record: dict) -> str:
    try:
        atproto.write_record(user, COLLECTION, rkey, record)
    except Exception as exc:
        raise SceneNotesError("could not save the note") from exc
    return rkey
