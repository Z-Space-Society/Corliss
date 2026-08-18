# Corliss — ATProto login, OIDC out

Corliss lets people sign in with their **ATProto handle** (Bluesky et al.)
instead of yet another account, and re-exposes that session to your own
services as a standard **OIDC provider**.

It is a bridge between two protocols:

- **In** — a full ATProto OAuth *client*: handle → DID → PDS discovery → PAR +
  PKCE + DPoP + `private_key_jwt`, ending in a DID-keyed Django session.
- **Out** — an OIDC *provider*: discovery, authorize, token, JWKS, minting an
  RS256 `id_token` whose `sub` is the member's DID.

Anything that speaks OIDC (Open WebUI, Grafana, …) can sit behind it.

Signing in is not the same as being allowed in, so there is a third, much
smaller surface: Corliss caches **who is a member** from an external registry
that pushes grants and revocations to it. See
[Membership](#membership-who-is-allowed-in).

## Layout

Corliss is a **single Django app**. Four models, one URL table; the protocol
halves are plain modules, not sub-apps. A future subsystem earns its own app
only by being genuinely standalone.

| Module | Responsibility |
| ------ | -------------- |
| `corliss/models.py` | `User` (DID-keyed), `AtprotoToken` (server-side PDS tokens + DPoP key), `OidcAuthCode`, `MembershipCache`. |
| `corliss/atproto.py` | ATProto OAuth client: client metadata, DPoP, handle/DID resolution, PDS discovery, PAR, token exchange. |
| `corliss/oidc.py` | OIDC provider core: discovery document, auth-code issuance, `id_token` minting. |
| `corliss/membership.py` | Consuming the registry's membership push; reconciling the cache against the registry; resolving whether a DID is currently a member. |
| `corliss/views.py` | Every HTTP endpoint, both halves. |
| `corliss/urls.py` | Every route, flat and un-namespaced. |
| `corliss/signing.py` | Loads the signing keys, builds the JWKS. |
| `corliss/version.py` | Resolves which build is running, for the footer's stamp (see [Releases](#releases)). |

Two signing keys, one JWKS: **ES256 (P-256)** for atproto DPoP + client
assertion (atproto mandates it) and **RS256 (RSA)** for the OIDC `id_token`
(broad OIDC-client compatibility).

## Run locally

Requires [uv](https://docs.astral.sh/uv/) and a reachable Postgres.

```bash
uv sync                         # builds .venv from uv.lock on Python 3.14

cp .env.example .env            # then edit DATABASE_URL etc.
createdb corlissdb              # or point DATABASE_URL at an existing DB
./manage.py generate_keys       # dev signing keys, written to ./keys/

./manage.py migrate
./manage.py collectstatic --noinput   # whitenoise manifest storage needs this
./manage.py runserver
```

`manage.py` carries a `#!/usr/bin/env -S uv run` shebang, so `./manage.py …`
syncs the environment from the lockfile and runs in one step — there is no venv
to activate. `uv run python manage.py …` is the explicit equivalent.

Configuration is entirely env-driven — see [`.env.example`](.env.example) for
the full list. `.env` is git-ignored; **never commit secrets or private keys**.
`CHAT_URL` drives the nav's "Chat" link, `MANAGE_URL` the "Manage Console" entry
in its Manage menu, and `API_URL` the endpoint shown on `/api/`. Each can be
left blank, which simply hides what it feeds.

The nav's two admin links answer to **two different authorities**, deliberately:
"Manage Console" to the atproto admin roster (`user.is_cluster_admin`), and
"Django admin" to Django's own `is_superuser`. A roster edit must not hand
anyone the Django admin, where the session and OIDC client tables live — see
[Membership](#membership-who-is-allowed-in). Use `manage.py make_admin` for the
latter.

### Why atproto login can't work over localhost

The authorization server fetches our `client-metadata.json` **server-side** over
public HTTPS — the `client_id` *is* that URL. Loopback is not reachable from
Bluesky's entryway, so no amount of local configuration makes a real login
complete. Nothing is misconfigured when this fails; it is the protocol.

atproto does define a development exception (a `client_id` with origin
`http://localhost`, carrying `redirect_uri` and `scope` as query parameters).
Corliss deliberately does not use it. It requires an empty path and no port,
which our `client_id` — `<PUBLIC_BASE_URL>/auth/client-metadata.json` — can
never satisfy; it forces `token_endpoint_auth_method: none`, making Corliss a
*public* client, so the `private_key_jwt` client assertion we actually deploy
would never execute; and the auth server synthesizes metadata rather than
fetching ours, skipping the document most likely to be misconfigured. It is
lowest fidelity exactly where this app is most likely to break.

So there are two local workflows, for two different jobs.

#### Local dev without atproto (the common case)

For the OIDC half, the templates, the admin, and relying-party wiring — none of
which needs the handshake — enable the development sign-in:

```bash
DEV_LOGIN_ENABLED=true      # in .env, alongside DEBUG=true
```

The login page then offers a second box that signs you in as any handle you
type. Members it creates are keyed on `did:dev:<handle>` — `did:dev` is not a
registered DID method, so these rows can never collide with a real atproto DID
and are obvious as fakes in the admin.

**This is a complete authentication bypass** — it verifies nothing. Three
guards keep it local: it is off by default, the route is only registered when
`DEBUG` and `DEV_LOGIN_ENABLED` are both true (and the view re-checks), and
`manage.py check` **errors** if the flag is set without `DEBUG`, so a
production env file carrying it fails the deploy's `migrate`/`collectstatic`
rather than quietly serving an open door.

It proves nothing about the atproto client. Use a tunnel for that.

The admin surface needs a second hatch, for a different reason: admin-ness is
read from a record in the SCN service DID's repo, so until that record exists
there is no way to be an admin at all — locally or anywhere.

```bash
DEV_ADMIN_DIDS=did:dev:you.bsky.social   # alongside DEBUG=true
```

Those DIDs answer yes to `is_cluster_admin` and to nothing else: no membership,
no Django flag, exactly as the real roster grants nothing but itself. Same
`DEBUG` requirement and the same `manage.py check` failure if it is set without
one. It does **not** grant the Django admin — that is `is_superuser`, via
`manage.py make_admin`.

#### Real atproto login locally (a named tunnel)

A quick `cloudflared tunnel --url http://127.0.0.1:8000` works, but its
hostname changes every run and three env vars have to chase it. A **named**
tunnel gets a stable hostname you configure once:

```bash
cloudflared tunnel login
cloudflared tunnel create corliss-dev
cloudflared tunnel route dns corliss-dev corliss-dev.example.com
```

Then in `.env` — all three, since Django rejects the host otherwise and the
`client_id` must match what the auth server fetches:

```bash
PUBLIC_BASE_URL=https://corliss-dev.example.com
CSRF_TRUSTED_ORIGINS=https://corliss-dev.example.com
ALLOWED_HOSTS=corliss-dev.example.com,localhost,127.0.0.1
```

Run the tunnel alongside `runserver`:

```bash
cloudflared tunnel run --url http://127.0.0.1:8000 corliss-dev
```

Confirm the auth server can see what it needs before trying to log in — this is
the same fetch it will make:

```bash
curl https://corliss-dev.example.com/auth/client-metadata.json
```

This exercises the true production path: PAR, PKCE, DPoP, `private_key_jwt`,
and a real metadata fetch.

### Tests

```bash
./manage.py collectstatic --noinput   # once; page tests render {% static %}
./manage.py test
```

### Checking for updates

Dependencies are declared in [`pyproject.toml`](pyproject.toml) and pinned —
exactly, by `==` — with the full tree including transitives locked in
[`uv.lock`](uv.lock). Both are committed, so every environment resolves to the
same versions. Upgrades are therefore always a deliberate, reviewable edit
rather than a silent drift at install time.

To see what has moved upstream:

```bash
uv tree --outdated --depth 1   # direct dependencies, current vs latest
uv pip list --outdated         # the whole installed tree
```

To take an upgrade, edit the `==` pin in `pyproject.toml`, then:

```bash
uv lock                        # re-resolve, re-pinning transitives around it
uv sync
./manage.py test
```

Note that `uv lock --upgrade` will not move a direct dependency here — an exact
pin leaves the resolver no room. It does still refresh transitives, which is
worth doing periodically on its own.

### Releases

Every page footer carries a build stamp — `Corliss v0.2.0`, linking the repo and
that tag — so the running version is readable off the site itself. It comes from
`git describe --tags --always --dirty` against the checkout
([`corliss/version.py`](corliss/version.py)), falling back to
`pyproject.toml`'s `version` where there is no `.git`. A checkout past its tag
reads `v0.2.0-3-gabc1234` and links the commit; a dirty tree says so and links
nothing, because what's running isn't any commit GitHub could show.

Cut a release with:

```bash
bin/release 0.3.0     # bump, re-lock, test, commit, annotated tag — no push
bin/release --show    # reprint the deploy steps for the current tag
```

**`version` in `pyproject.toml` and the `vX.Y.Z` tag are one fact, and
`bin/release` is what keeps them that way.** The bump is not cosmetic even though
nothing imports the package: `uv.lock` records the project version, and the
deploy runs `uv sync --locked`, so bumping `pyproject.toml` without re-running
`uv lock` fails the deploy outright. The script always does both, runs the suite
before it will tag, and reverts the bump if the suite fails.

It stops at the tag rather than pushing, then prints the remaining steps —
push, pin `corliss_version` in [zai-ops](https://github.com/Z-Space-Society/zai-ops),
replay the role, confirm the live footer — as runnable commands. Tagging is only
half of shipping; the checklist is the other half, and lives in the script rather
than being duplicated here so there is one place for it to be correct.

### Admin

```bash
manage.py make_admin alice.bsky.social   # promote an ATProto identity (keyed on DID)
manage.py ensure_admin                   # idempotent break-glass local admin;
                                         #   reads CORLISS_ADMIN_PASSWORD
```

## Endpoints

| Endpoint | Path |
| -------- | ---- |
| Home | `/` |
| API access (placeholder) | `/api/` |
| Login / logout | `/auth/login`, `/auth/logout` |
| ATProto callback | `/auth/oauth/callback` |
| ATProto client metadata (**is** the `client_id`) | `/auth/client-metadata.json` |
| OIDC discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| OIDC authorize / token | `/oidc/authorize`, `/oidc/token` |
| Membership push (from the registry) | `/membership/events` |
| Console — members, admins, reconcile (cluster admins) | `/manage/` |
| Django admin | `/admin/` |

Discovery and JWKS sit at the root deliberately: an OIDC issuer of
`https://example.com` must serve its discovery document at
`https://example.com/.well-known/openid-configuration`.

## Membership — who is allowed in

Corliss authenticates people; it does not decide who may use the cluster. That
lives in an external registry (append-only grant and revocation records, held
in a HappyView space). Corliss keeps a **cache** of the registry's answer in
`MembershipCache`, and the registry is authoritative in every disagreement.

**The registry pushes; Corliss never pulls.** A pull would require Corliss to
authenticate to the registry as itself, which is unsolved. Pushing removes the
question. On each grant or revocation the registry POSTs to
`/membership/events`, authenticated by a shared bearer token
(`MEMBERSHIP_PUSH_TOKEN`):

```json
{ "event": "grant",
  "did": "did:plc:…",
  "rkey": "did:plc:…:3lqx7qzabc2de",
  "authorDid": "did:plc:…",
  "record": { "status": "active", "grantedAt": "…", "tier": "level-2" } }
```

`event` is `grant` or `revoke`; a revocation's record carries `revokedAt` and
an optional `reason` instead of a tier. The envelope fields are exactly the
metadata the registry returns alongside a record, so a future reconciliation
pass reading the registry directly fills the same shape.

Four properties that are easy to get wrong:

- **Unset `MEMBERSHIP_PUSH_TOKEN` closes the endpoint** with a 503. It is never
  open when unconfigured — comparing against `""` would accept a request that
  also sent nothing.
- **Events are ordered by the rkey's TID, never by the timestamps.** The
  registry writes second-resolution timestamps, so they cannot separate two
  events in the same second, and a grant retried after a revocation would
  otherwise sort last and silently re-admit a revoked member.
- **A replayed or stale event returns 200 with `applied: false`.** Push is
  best-effort, so duplicates are normal and must not read as failures.
- **`MembershipCache` is keyed by DID, not by a FK to `User`.** A grant can be
  written for someone who has never logged in — that is how an invitation
  works. `membership.membership_for(user)` bridges the two.

Drive it locally without the registry:

```bash
bin/push-grant did:plc:abc… level-2         # grant, or change tier
bin/push-grant --revoke did:plc:abc…        # revoke
bin/push-grant --replay did:plc:abc… <rkey> # prove a stale event is a no-op
```

### Reconciliation — rebuilding the cache from the registry

The push keeps the cache *fresh*. It cannot *build* it: a Corliss rebuilt from
scratch has witnessed nothing, and the events it missed already happened, so
nothing will send them again. `membership.reconcile(events, roster)` is the
other direction — read every grant and revocation from the registry space and
re-derive the cache from them. It is what makes an empty database recoverable,
and therefore a prerequisite for ever gating access on the cache.

It is keyed by DID with no foreign key to `User`, so **a reconcile run needs no
login and no user rows at all** — it can repopulate membership on a database
nobody has ever signed in to.

Two ways to run it, one code path — `MembershipRegistry.reconcile` — so a click
and a scheduled run can never mean different things:

```bash
manage.py reconcile_membership --dry-run   # report only, writes nothing
manage.py reconcile_membership             # apply; non-zero exit if incomplete
```

…or the **Reconcile memberships** button on `/manage/`. The command exits
non-zero on an incomplete report on purpose: a scheduled run that logged success
over a half-empty cache would be worse than not running at all.

- **The events must come from the registry space** — an `atproto.spaces.query`,
  never the firehose index and never a repo read. The grant lexicon is
  published, so anyone can write a `membership.grant` into their own PDS and
  have it indexed; what makes a grant real is being *in the space*.
- **Authority is asked at the event's timestamp**, via `Roster.was_admin_at`.
  Removing an admin ends their authority going forward and does not un-write
  what they already approved — asking "is this DID an admin now" would silently
  de-member everyone a departed admin ever let in.
- **Only the winning event is parsed.** Events are resolved latest-per-DID by
  the rkey's TID first, because historically-shaped records are permanent in an
  append-only log and replaying all of them would fail on records that can never
  be removed.
- **`unresolved` and `orphans` are blockers, not warnings.** An unresolved DID
  is a member missing from the cache. An orphan is a cache row with no
  admin-authored event behind it — precisely what a leaked push token leaves.
  Orphans are reported, never pruned here.
- `dry_run=True` reports what a run would do without writing anything.

**How it reads the space.** `MembershipRegistry` calls `syncMembers`, a
read-only registry endpoint authenticated by a shared token
(`MEMBERSHIP_REGISTRY_TOKEN`) rather than by a signed-in admin — because the run
that matters most happens at boot with nobody present. It is an XRPC **query**,
so the token travels as a URL parameter: the registry gates *procedures* behind
DPoP authentication, which a service holding only a shared token cannot provide.
Point `MEMBERSHIP_REGISTRY_URL` at the registry's **internal** address for that
reason — it keeps the token out of any edge or CDN log. It is deliberately a
*different door* from the admin-authenticated `listMembers` the console uses, so
the two credentials rotate independently and widening one cannot widen the
other. `MEMBERSHIP_REGISTRY_URL` or `MEMBERSHIP_REGISTRY_TOKEN` blank disables
reconciliation with a visible reason rather than a traceback.

`MEMBERSHIP_REGISTRY_CLIENT_KEY` is **optional** — sent when set, omitted when
not. Verified against production: HappyView dispatches to a Lua script with no
session and no client key at all, so the key adds nothing the token does not
already carry. Requiring it would tie reconciliation to the *console's*
origin-bound key having been configured, and the recovery path must not depend on
the console it replaces.

The registry returns `{rkey, authorDid, record}` with no `did` and no `event`.
Both are recovered without guessing — `event` is which array the entry arrived
in, `did` is `did_of(rkey)` — which is what lets the push and the read share one
parser instead of drifting into two shapes for one lexicon.

Not built yet: the systemd timer and the run at boot. Those land once a real run
against production has reported clean.

## The console — `/manage/`

Members, admins, and reconciliation, for cluster admins. Gated on
`is_cluster_admin` — a live roster read — and **never on `is_superuser`**. That
is what keeps it reachable on a cluster rebuilt from nothing: the roster needs no
database and no cache, so an admin can arrive with `MembershipCache` empty and
every member locked out, and press the button that fills it. The recovery action
sits behind the one door that does not depend on the thing being recovered.

The two tables come from different places, and the difference is the point:
members are Corliss's own cache (can be stale, incomplete, or orphaned); admins
are read live from the registry's public roster record (nothing to go stale). A
roster that cannot be read renders as a failure, not an empty table — "could not
find out" and "there are no admins" are different facts.

This page supersedes the separate SPA admin console. The write surface (approve,
revoke, set tier, roster edits) still lives there and moves here next; those are
*writes* to the registry space and must keep requiring a current-admin caller, so
`MEMBERSHIP_REGISTRY_TOKEN` must never gain write scope.

## Wiring up a relying party (Open WebUI shown)

```bash
ENABLE_OAUTH_SIGNUP=true
OAUTH_CLIENT_ID=open-webui                       # must equal OIDC_CLIENT_ID here
OAUTH_CLIENT_SECRET=<shared secret>              # must equal OIDC_CLIENT_SECRET here
OPENID_PROVIDER_URL=https://<PUBLIC_BASE_URL>/.well-known/openid-configuration
OAUTH_SCOPES=openid email profile
OAUTH_USERNAME_CLAIM=handle                      # we emit `handle` (= the atproto handle)
OAUTH_EMAIL_CLAIM=email                          # present when the member's PDS supplied one
```

Register the RP's redirect URI in Corliss's `OIDC_REDIRECT_URIS`
(e.g. `https://chat.example.com/oauth/oidc/callback`).

**`id_token` claims:** `sub` = DID, `handle` (also `preferred_username`),
`iss`/`aud`/`exp`/`iat`/`nonce`, plus `email` + `email_verified` when the
member's PDS supplied one. Email is best-effort — sourced at login via the
`transition:email` scope and `com.atproto.server.getSession` — so a member who
declines the scope simply gets no `email` claim. DID is the only stable
identifier; never key on handle or email.

## Deployment

Corliss runs under gunicorn + whitenoise against Postgres; every deployment
value is an environment variable, so it has no opinion about how it's shipped.
It is deployed to the Z-Space AI cluster by the `corliss` Ansible role in
[zai-ops](https://github.com/Z-Space-Society/zai-ops), which clones this repo
at a pinned ref, provisions the venv with `uv sync --locked --no-dev`,
migrates, collects static, and renders the env file. `--locked` makes the
deploy fail loudly if `uv.lock` is stale against `pyproject.toml` rather than
quietly resolving something else, so the cluster runs the exact tree committed
here. The interpreter is a uv-managed CPython 3.14 — Debian 13's system Python
is 3.13, so the role fetches its own rather than using the distro's.

Because the role clones a pinned **tag** into a full checkout, the footer's build
stamp on the deployed site reports exactly the released version — the quickest
way to confirm a deploy actually landed (see [Releases](#releases)).

Required in production: `SECRET_KEY`, `DATABASE_URL`, `ALLOWED_HOSTS`,
`PUBLIC_BASE_URL`, `CSRF_TRUSTED_ORIGINS`, the two key paths, and the
`OIDC_CLIENT_*` values.

> **History:** Corliss began as the `zai-auth` app inside
> [zai-ops](https://github.com/Z-Space-Society/zai-ops) and was extracted here;
> pre-extraction history lives in that repo.

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant, and
compatible with the ATProto ecosystem's own MIT/Apache-2.0 licensing.
