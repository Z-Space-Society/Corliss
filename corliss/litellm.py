"""LiteLLM, as something Corliss provisions members into.

This is the half of Corliss that turns a membership grant into working API
access. It holds the only LiteLLM credential in the cluster outside CT 100: a
provisioner key that can mint, list and delete keys for *anyone*, which is why
every method here re-establishes on the server which member is asking rather
than trusting what the client sent.

**The credential is the whole reason this module is shaped the way it is.**
Issuing proves active membership; revoking proves the key belongs to the
caller. A client may never aim the provisioner key at another member. That rule
came out of the pre-strip HappyView Lua (`issue_key.lua`, `revoke_key.lua` in
scn-ops at `ad9b424^`) and survives the port unchanged, because the thing it
guards against did not change.

Like `MembershipRegistry` in `corliss.membership` and back-channel logout in
`corliss.oidc`, this module owns its own transport. One relationship, one file.

**Keys are not stored here.** LiteLLM is the source of truth: `/api/` lists
them live, and the plaintext exists for exactly one render. A key Corliss
persisted would be a credential in a second place for no gain — it cannot be
re-shown, and LiteLLM already knows every fact about it worth reading.

**No `Host` header, deliberately.** The registry client next door presents one
because HappyView routes by virtual host and answers a bare-IP `Host` with HTTP
421. LiteLLM does not route that way, so reaching it at `10.1.1.x:4000` needs
nothing extra. The absence is a fact about LiteLLM, not an oversight.

**This module must not import `corliss.membership`.** Membership calls *into*
here on grant and revocation, so the dependency runs one way only. Anything
this needs from there — the member's handle, their tier — arrives as an
argument.
"""

import logging
import re

import requests
from django.conf import settings
from django.core.cache import cache

log = logging.getLogger(__name__)


class LiteLLMError(Exception):
    """LiteLLM could not be reached, refused us, or answered unusably.

    Carries a message meant for a member to read on `/api/`, so it says what
    happened without naming the credential or the internal address.
    """


# Key issuance and the key list both sit on a human's request for a page, so
# the bound is the one back-channel logout uses for the same reason, not the
# 30s the registry gets for an operator-triggered reconcile.
LITELLM_TIMEOUT = 5

# Alias→id for the tier teams. They change only when Ansible runs, but a stale
# *miss* is worse than a stale hit here: a miss refuses issuance (see
# `team_id_for`), so this is short enough that a freshly-created team becomes
# usable without a restart.
_TEAM_CACHE_KEY = "corliss:litellm:teams"
TEAM_CACHE_TTL = 300

# A key's label, as typed by a member. Ported from `issue_key.lua`: printable,
# starts alphanumeric, and short enough to read in a table. It ends up inside
# an alias LiteLLM admins scan, so slashes are excluded — the alias uses one as
# its own separator.
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
MAX_LABEL_LEN = 64

# The key *hash* LiteLLM identifies a key by. Not a credential, and not the
# `sk-…` secret — see `ApiKey.token`.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9]+$")

# Substrings LiteLLM puts in the body when the thing we asked for is already
# true. Matching on prose is brittle and there is no better signal: these three
# calls answer 400, not 200, when they are already satisfied, and re-running
# provisioning has to be a no-op rather than an error. Verified against the
# pinned LiteLLM; re-check them when that pin moves.
_ALREADY_EXISTS = ("already exist",)
_ALREADY_A_MEMBER = ("already",)
_NOT_A_MEMBER = ("not found", "does not exist")


class ApiKey:
    """One LiteLLM key, as `/api/` renders it. Never the secret."""

    __slots__ = (
        "token", "masked", "alias", "spend", "created_at", "blocked", "team_id",
    )

    def __init__(self, *, token, masked, alias, spend, created_at, blocked,
                 team_id=None):
        # LiteLLM's `token` is the key's hash. It identifies the key for
        # revocation and is safe to put in a form; the `sk-…` value it hashes
        # is shown once at creation and never stored anywhere.
        self.token = token
        self.masked = masked  # e.g. "sk-...4f2a"
        self.alias = alias
        self.spend = spend
        self.created_at = created_at
        self.blocked = blocked
        # The team the key was minted against — which is what governs its model
        # access, and which LiteLLM will not let us change afterwards. See
        # `prune_foreign_keys`.
        self.team_id = team_id

    @property
    def label(self):
        """The half of the alias the member typed.

        Aliases are stored `<handle>/<label>` so a LiteLLM admin can attribute
        a key at a glance; a member only ever needs their own half back.
        """
        if not self.alias:
            return "(unnamed)"
        head, sep, tail = self.alias.partition("/")
        return tail if sep else head


class LiteLLM:
    """The cluster's LiteLLM proxy, as a thing Corliss provisions into.

        litellm = LiteLLM.from_settings()
        secret = litellm.issue_key(did, "laptop", handle="jacob.example", tier="level-2")

    Constructed with its configuration rather than reaching for `settings`
    inside every method, so a test can point it anywhere and never touch the
    network.
    """

    __slots__ = ("url", "token", "max_keys")

    def __init__(self, url, token, max_keys=5):
        self.url = (url or "").rstrip("/")
        self.token = token or ""
        self.max_keys = max_keys

    @classmethod
    def from_settings(cls):
        return cls(
            settings.LITELLM_URL,
            settings.LITELLM_PROVISIONER_KEY,
            settings.LITELLM_MAX_KEYS_PER_MEMBER,
        )

    @property
    def is_configured(self):
        """The url and the provisioner key. Asked before offering to act, so
        an unconfigured deployment shows a reason rather than a traceback —
        the same posture `MembershipRegistry.is_configured` takes."""
        return bool(self.url and self.token)

    # --- transport ---------------------------------------------------------

    def _call(self, method, path, *, params=None, body=None, tolerate=()):
        """One LiteLLM call. Returns the decoded body, or raises `LiteLLMError`.

        `tolerate` is a tuple of substrings that turn a 4xx into a success with
        no body — the "it was already true" case, which every idempotent step
        here depends on. See `_ALREADY_EXISTS` for why it is matched on prose.

        Transport failure and HTTP status are checked separately and both are
        handled, which is what the Lua's `pcall`-then-check-status did. A bare
        `raise_for_status()` would collapse them into one exception and lose
        the body, which is where LiteLLM puts the reason.
        """
        if not self.is_configured:
            raise LiteLLMError(
                "LiteLLM is not configured: LITELLM_URL and "
                "LITELLM_PROVISIONER_KEY must both be set"
            )

        try:
            response = requests.request(
                method,
                f"{self.url}{path}",
                params=params,
                json=body,
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=LITELLM_TIMEOUT,
            )
        except requests.RequestException as exc:
            # Never let the URL into the message: it carries the internal
            # address, and this text is rendered to a member.
            log.warning("litellm: %s %s failed: %s", method, path, exc)
            raise LiteLLMError("the API service could not be reached") from exc

        if response.status_code >= 400:
            text = response.text or ""
            if any(fragment in text.lower() for fragment in tolerate):
                return {}
            log.warning(
                "litellm: %s %s returned %s: %s",
                method,
                path,
                response.status_code,
                text[:300],
            )
            raise LiteLLMError(
                f"the API service refused the request (HTTP {response.status_code})"
            )

        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise LiteLLMError("the API service answered with something unreadable") from exc

    # --- teams: the tier map -----------------------------------------------

    def teams(self, *, refresh=False):
        """Every team, as `{team_alias: team_id}`.

        Teams are created by the `litellm` role in zai-ops, one per tier slug,
        and resolved here by alias rather than by an id baked into config —
        an id is generated at creation time and would have to be carried out of
        Ansible by hand, which is the class of manual step the cluster's prime
        directive exists to delete.
        """
        if not refresh:
            cached = cache.get(_TEAM_CACHE_KEY)
            if cached is not None:
                return cached

        payload = self._call("GET", "/team/list")
        entries = payload if isinstance(payload, list) else payload.get("teams") or []
        found = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            alias, team_id = entry.get("team_alias"), entry.get("team_id")
            if alias and team_id:
                found[alias] = team_id

        cache.set(_TEAM_CACHE_KEY, found, TEAM_CACHE_TTL)
        return found

    def team_id_for(self, tier):
        """The team a tier maps to. Raises when the tier has no team.

        **Fails closed, and that is the point.** A key with no `team_id` is
        *more* permissive than one with the wrong team, not less: LiteLLM
        scopes model access through the team, so an unscoped key inherits
        whatever the user can reach, which on a proxy with no per-user model
        list is everything. Issuing one because the team lookup came up empty
        would hand a `level-0` member the whole model catalogue and look like
        success.

        A blank tier is a different case and is allowed through as None —
        `is_active_member` gates entry, and a member whose grant predates tiers
        should not be silently upgraded either.
        """
        if not tier:
            return None
        team_id = self.teams().get(tier)
        if team_id is None:
            # One retry past the cache: a team created by an Ansible run a
            # minute ago should not be invisible for the rest of the TTL.
            team_id = self.teams(refresh=True).get(tier)
        if team_id is None:
            raise LiteLLMError(
                f"no API tier is configured for {tier!r} yet — "
                "an administrator needs to create it before keys can be issued"
            )
        return team_id

    # --- users -------------------------------------------------------------

    def ensure_user(self, did, *, handle="", tier=""):
        """Make LiteLLM's picture of this member match ours. Idempotent.

        **The LiteLLM `user_id` IS the DID** — not the handle, not a hash.
        That is what makes `/user/new` idempotent on retry, which is what makes
        provisioning safely repeatable without a transaction, which is what
        lets this be called from a push, from a page load, and from
        `sync_litellm` without any of them coordinating.

        Returns the team id the member now belongs to, or None.
        """
        body = {"user_id": did, "auto_create_key": False}
        if handle:
            body["user_alias"] = handle
        self._call("POST", "/user/new", body=body, tolerate=_ALREADY_EXISTS)

        team_id = self.team_id_for(tier)
        self.set_team(did, team_id)
        return team_id

    def set_team(self, did, team_id):
        """Put the member in exactly `team_id`, and in no other team.

        `None` removes them from every team, which is what revocation wants:
        a member with no team reaches no tier's models.
        """
        info = self._call("GET", "/user/info", params={"user_id": did}) or {}
        user = info.get("user_info") or info
        current = [t for t in (user.get("teams") or []) if isinstance(t, str)]

        for stale in current:
            if stale != team_id:
                self._call(
                    "POST",
                    "/team/member_delete",
                    body={"team_id": stale, "user_id": did},
                    tolerate=_NOT_A_MEMBER,
                )

        if team_id and team_id not in current:
            self._call(
                "POST",
                "/team/member_add",
                body={
                    "team_id": team_id,
                    "member": {"user_id": did, "role": "user"},
                },
                tolerate=_ALREADY_A_MEMBER,
            )

    # --- keys --------------------------------------------------------------

    def keys_for(self, did):
        """This member's keys, newest first. Never anyone else's.

        The `user_id` filter is applied twice — once as a query parameter and
        again over the response. Belt and braces: the parameter is what makes
        the call cheap, the re-filter is what makes it *correct* if a LiteLLM
        version ever ignores it. Handing one member another's key list would be
        this module's worst failure and it costs one comparison to rule out.
        """
        payload = self._call(
            "GET",
            "/key/list",
            params={"return_full_object": "true", "size": 100, "user_id": did},
        )
        entries = payload.get("keys") if isinstance(payload, dict) else None
        keys = []
        for entry in entries or []:
            if not isinstance(entry, dict) or entry.get("user_id") != did:
                continue
            keys.append(
                ApiKey(
                    token=entry.get("token") or "",
                    masked=entry.get("key_name") or "",
                    alias=entry.get("key_alias") or "",
                    spend=entry.get("spend") or 0,
                    created_at=entry.get("created_at") or "",
                    blocked=bool(entry.get("blocked")),
                    team_id=entry.get("team_id"),
                )
            )
        keys.sort(key=lambda k: k.created_at, reverse=True)
        return keys

    def issue_key(self, did, label, *, handle="", tier=""):
        """Mint a key for this member and return the secret, once.

        The caller has already proved membership; this proves the *shape* of
        what was asked for and that the member is under their cap. LiteLLM has
        no per-user key limit, so the cap is ours or there is none.

        The returned string is the only copy that will ever exist. It is not
        written to the database, not logged, and not returned again.

        **A tier is required, and that is a security check rather than a
        formality.** `team_id_for` allows a blank tier through as "no team",
        which is right for `ensure_user` — the five pre-E0 grants in the
        production space carry no tier and their holders should still exist in
        LiteLLM. It is wrong here: a key with no team inherits every model, so
        minting one for a tierless grant would silently hand out more than the
        registry ever granted. The same applies to a roster admin who passed
        GATE without a grant of their own.
        """
        if not tier:
            raise LiteLLMError(
                "your membership carries no tier yet, so there is nothing to "
                "scope a key to — ask an administrator to set one"
            )

        label = (label or "").strip()
        if not label or len(label) > MAX_LABEL_LEN or not _LABEL_RE.match(label):
            raise LiteLLMError(
                "a key name must be 1–64 characters: letters, numbers, "
                "spaces, dots, dashes and underscores"
            )

        held = self.keys_for(did)
        if len(held) >= self.max_keys:
            raise LiteLLMError(
                f"you already have {len(held)} keys, which is the limit "
                f"({self.max_keys}) — revoke one first"
            )

        team_id = self.ensure_user(did, handle=handle, tier=tier)

        # `<handle>/<label>`, so a LiteLLM admin can tell whose key is whose at
        # a glance. The handle is display only and may change; `user_id` is
        # what ownership is decided on, here and in `revoke_key`.
        alias = f"{handle or did}/{label}"
        body = {"user_id": did, "key_alias": alias}
        if team_id:
            body["team_id"] = team_id

        created = self._call("POST", "/key/generate", body=body)
        secret = created.get("key") if isinstance(created, dict) else None
        if not isinstance(secret, str) or not secret:
            raise LiteLLMError("the API service did not return a key")
        return secret

    def revoke_key(self, did, token):
        """Delete one key, after proving it belongs to this member.

        **Ownership is re-established here, server-side, every time.** The
        provisioner key can delete anyone's; the token arrives in a form post
        and is therefore whatever the client chose to send. Looking it up in
        *this* DID's key list first is what stops the credential being aimed by
        its caller.
        """
        token = (token or "").strip()
        if not token or not _TOKEN_RE.match(token):
            raise LiteLLMError("that is not a key identifier")

        if not any(key.token == token for key in self.keys_for(did)):
            log.warning("litellm: %s tried to revoke a key they do not own", did)
            raise LiteLLMError("that key is not yours")

        self._call("POST", "/key/delete", body={"keys": [token]})

    def delete_keys_for(self, did):
        """Delete every key this member holds. Returns how many.

        The revocation path. Ownership needs no separate proof here because the
        subject is the DID itself rather than a token someone submitted.
        """
        tokens = [key.token for key in self.keys_for(did) if key.token]
        if tokens:
            self._call("POST", "/key/delete", body={"keys": tokens})
        return len(tokens)

    def prune_foreign_keys(self, did, team_id):
        """Delete this member's keys that belong to any other team. Returns how
        many.

        **This is what a tier change costs, and it is not a design choice.**
        LiteLLM refuses to move an existing key between teams — `/key/update`
        with a new `team_id` answers **403** and the key does not move (verified
        against the deployed proxy, 2026-08-19). A key's model access and budget
        come from the team it was minted against, so after a tier change the old
        keys still carry the old tier.

        Leaving them is the unsafe direction: a member moved *down* a tier would
        keep the access they just lost, silently and indefinitely. So the keys
        go and the member issues new ones. That applies to an upgrade too —
        uniformly, because a rule that deletes on the way down and not on the way
        up is one nobody can predict, and the alternative on the way up is an
        upgrade that visibly does nothing.

        Deliberately keyed on the team rather than on "did the tier change",
        which this has no way to know: a key already on the right team is left
        alone. That is what keeps a reconcile replay on a rebuilt cluster quiet —
        it re-applies every grant, and every key is already where it belongs.
        """
        stale = [
            key.token
            for key in self.keys_for(did)
            if key.token and key.team_id != team_id
        ]
        if stale:
            self._call("POST", "/key/delete", body={"keys": stale})
            log.info(
                "litellm: deleted %s key(s) for %s left on another tier's team",
                len(stale),
                did,
            )
        return len(stale)

    # --- usage -------------------------------------------------------------

    def usage(self, did, start_date, end_date):
        """This member's daily usage, one row per (day, model), plus totals.

        Read from LiteLLM's daily aggregate tables rather than request logs:
        the proxy runs with `disable_spend_logs` on, and the aggregates are
        what survives that.

        A missing `user_id` here would return the *entire* proxy's usage, so
        the caller passing a DID is not optional and never comes from a form.
        """
        if not did:
            raise LiteLLMError("no member to report usage for")

        payload = self._call(
            "GET",
            "/user/daily/activity",
            params={
                "user_id": did,
                "start_date": start_date,
                "end_date": end_date,
                "page_size": 100,
            },
        )
        if not isinstance(payload, dict):
            raise LiteLLMError("the API service answered with something unreadable")

        rows = []
        for day in payload.get("results") or []:
            if not isinstance(day, dict):
                continue
            # `model_groups` before `models`: the former is keyed by the name
            # a member actually requests (`nomic-embed-text`), the latter by
            # the upstream route it maps to (`openai/nomic-embed-text`). A
            # member's own usage table should name what they typed. Falls back
            # for a LiteLLM that does not break usage down that way.
            breakdown = day.get("breakdown") or {}
            models = breakdown.get("model_groups") or breakdown.get("models") or {}
            for model, entry in models.items():
                metrics = (entry or {}).get("metrics") or {}
                rows.append(_usage_row(day.get("date"), model, metrics))
            if not models:
                # A day whose requests never reached a model — failures,
                # mostly — still gets a row, so usage is not silently missing.
                metrics = day.get("metrics") or {}
                if (metrics.get("api_requests") or 0) > 0:
                    rows.append(_usage_row(day.get("date"), "", metrics))

        rows.sort(key=lambda r: (r["date"] or "", r["model"]), reverse=True)

        meta = payload.get("metadata") or {}
        totals = {
            "prompt_tokens": meta.get("total_prompt_tokens") or 0,
            "completion_tokens": meta.get("total_completion_tokens") or 0,
            "total_tokens": meta.get("total_tokens") or 0,
            "requests": meta.get("total_api_requests") or 0,
        }
        return rows, totals


def _usage_row(date, model, metrics):
    return {
        "date": date or "",
        "model": model or "",
        "prompt_tokens": metrics.get("prompt_tokens") or 0,
        "completion_tokens": metrics.get("completion_tokens") or 0,
        "total_tokens": metrics.get("total_tokens") or 0,
        "requests": metrics.get("api_requests") or 0,
    }


# --- Membership lifecycle ---------------------------------------------------
#
# What `membership.apply_event` calls when the cache changes. Both of these
# **never raise**, for the same reason `oidc.notify_logout` does not: the event
# that triggered them has already been committed here and already happened in
# the registry, so turning a LiteLLM outage into a failed push would report a
# failure for something that succeeded — and the Lua would log it as one.
#
# What makes that safe rather than merely quiet is `sync_litellm`, which
# re-derives all of this from the cache. A dropped notification costs a stale
# LiteLLM until that runs; it does not cost the fact.


def on_membership_granted(did, tier, *, handle=""):
    """A member was granted, or moved tier. Make LiteLLM agree.

    **Provisioning before first request is the point.** LiteLLM's spend
    accounting silently no-ops for a user it has never heard of — no upsert, no
    error, and the logs look right while the member's spend stays 0.0. So the
    user has to exist before a key can be used, not after.
    """
    client = LiteLLM.from_settings()
    if not client.is_configured:
        return False
    try:
        team_id = client.ensure_user(did, handle=handle, tier=tier)
        # After the user has been moved, not before: a failure here should leave
        # the member in the right team with stale keys, not the reverse.
        client.prune_foreign_keys(did, team_id)
    except LiteLLMError as exc:
        log.warning("litellm: could not provision %s (%s): %s", did, tier, exc)
        return False
    return True


def on_membership_revoked(did):
    """A live membership ended. Take the member's API access with it.

    Keys first, then the team. That order is deliberate and comes from the
    pre-strip `revoke_member.lua`: if the second half fails the member has
    already lost access, and a retry only needs to finish the paperwork. The
    other order leaves a working key behind a tidy-looking failure.
    """
    client = LiteLLM.from_settings()
    if not client.is_configured:
        return False
    try:
        deleted = client.delete_keys_for(did)
    except LiteLLMError as exc:
        log.warning("litellm: could not delete keys for %s: %s", did, exc)
        return False
    try:
        client.set_team(did, None)
    except LiteLLMError as exc:
        log.warning("litellm: could not remove %s from their team: %s", did, exc)
    log.info("litellm: revoked %s (%s key(s) deleted)", did, deleted)
    return True
