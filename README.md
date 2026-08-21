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

Corliss is a **single Django app**. Five models, one URL table; the protocol
halves are plain modules, not sub-apps. A future subsystem earns its own app
only by being genuinely standalone.

| Module | Responsibility |
| ------ | -------------- |
| `corliss/models.py` | `User` (DID-keyed), `AtprotoToken` (server-side PDS tokens + DPoP key), `OidcAuthCode`, `OidcSession`, `MembershipCache`. |
| `corliss/atproto.py` | ATProto OAuth client: client metadata, DPoP, handle/DID resolution, PDS discovery, PAR, token exchange. |
| `corliss/oidc.py` | OIDC provider core: discovery document, auth-code issuance, `id_token` minting, and back-channel logout (including the outbound POST — same one-relationship-one-module rule `membership.py` follows). |
| `corliss/membership.py` | The whole registry relationship: consuming its membership push, reconciling the cache against it, reading the application queue, writing grants and revocations as the acting admin, and resolving whether a DID is currently a member. |
| `corliss/litellm.py` | Provisioning members into LiteLLM and issuing their API keys — the only place a gateway credential is used (same one-relationship-one-module rule). |
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
in its Manage menu, and `API_URL` both the endpoint shown on `/api/` and the
"LiteLLM Admin" entry in the Manage menu (`API_URL` + `/ui/`, cluster admins
only — derived rather than configured separately, since a second setting for the
same origin could only ever disagree with the first). `HAPPYVIEW_URL` and
`PROXMOX_URL` add the other two service consoles to that menu; each is dropped
when blank. `PROXMOX_URL` is the odd one out — the Proxmox UI runs on the host
rather than behind the edge, so it has no subdomain of ours and points at the
LAN instead (self-signed cert, not reachable from outside).

Those three link *other systems'* admin UIs. Each authenticates on its own terms
with credentials Corliss does not hold, so they open a login rather than a
session — offered to cluster admins because that is who would have those
credentials, not because Corliss grants anything by linking them. Each can be
left blank, which simply hides what it feeds. The `LITELLM_*` trio is what makes
`/api/` able to issue keys rather than only describe them — see
[API keys](#api-keys--api).

The nav's two admin links answer to **two different authorities**, deliberately:
"Manage Console" to the atproto admin roster (`user.is_cluster_admin`), and
"Django admin" to Django's own `is_staff`. A roster edit must not hand anyone
the Django admin, where the session and OIDC client tables live — see
[Membership](#membership-who-is-allowed-in). Use `manage.py make_admin` for the
latter; it grants staff only, and `--superuser` — the flag that bypasses every
permission check — has to be asked for.

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
one. It does **not** grant the Django admin — that is `is_staff`, via
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
manage.py make_admin alice.bsky.social   # Django staff, keyed on DID (--superuser opts in
                                         #   to the flag that bypasses every check)
manage.py ensure_admin                   # idempotent break-glass local admin;
                                         #   reads CORLISS_ADMIN_PASSWORD
```

## Endpoints

| Endpoint | Path |
| -------- | ---- |
| Home | `/` |
| API keys — issue, revoke, usage (members) | `/api/` |
| Login / logout | `/auth/login`, `/auth/logout` |
| ATProto callback | `/auth/oauth/callback` |
| ATProto client metadata (**is** the `client_id`) | `/auth/client-metadata.json` |
| OIDC discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| OIDC authorize (members) / token | `/oidc/authorize`, `/oidc/token` |
| Membership push (from the registry) | `/membership/events` |
| Apply for membership (signed-in non-members) | `/membership/apply` |
| Console — decide applications, members, admins, reconcile (cluster admins) | `/manage/` |
| Systems — the stack, status stubbed (cluster admins) | `/systems/` |
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

### Applications — asking, and who has asked

An application is a `membership.request` record with rkey `self` in the
**applicant's own PDS** — one per account, world-readable, carrying a timestamp
and an optional short note and nothing else. Both ends of it live here: a
signed-in non-member writes one from the home page, and `/manage/` lists them
above the member roll.

#### Applying

The home page's apply form posts to `/membership/apply`, which writes the record
straight into the member's own repo with `com.atproto.repo.putRecord`
(`membership.submit_application` → `atproto.write_record`). Corliss already
holds that member's PDS tokens and DPoP key from login, so it needs no HappyView
session and no registry procedure to do it — which is the one structural
difference from how the Manage Console does the same thing.

- **Applying confers nothing, and never touches `MembershipCache`.** The record
  asks; only an admin's grant in the registry space answers. Nothing on the
  apply path reads or writes the cache.
- **The applicant's own state is read from their PDS, not from the index.**
  `listRequests` lags the write by however long the firehose takes, so an
  applicant who read their own status from it would click the button and watch
  nothing change. `membership.my_application` reads the record back with
  `atproto.find_record` and caches it briefly — that cache is what keeps the
  nav's `Membership: pending` from costing a round trip per page.
- **"No record" and "cannot reach your PDS" stay distinct.** A PDS reports a
  missing record as an HTTP 400 carrying `RecordNotFound`, so the status alone
  cannot separate them. When the read fails, the page says so and holds the form
  back rather than inviting a second application over the first.
- **The scope is narrow on purpose.** Corliss asks for
  `repo:network.sharedcomputer.membership.request?action=create&action=update&action=delete`
  — write access to that one collection — rather than `transition:generic`,
  which would be standing permission to write *any* record type into every
  member's repo for the sake of one record. See `atproto.SCOPE`.
- **A stale access token is the ordinary case.** A Django session outlives a PDS
  access token by a wide margin, so `atproto.write_record` refreshes on being
  told `invalid_token` and retries once. It refreshes on the PDS's say-so rather
  than on a clock, and it retries exactly once: a write that fails twice for the
  same reason will fail a third time.
- **Withdrawing is not built yet.** The scope above already permits the delete;
  what is unverified is whether the registry's firehose indexer processes one,
  and a withdraw button that leaves the row in an admin's queue would be worse
  than none.

#### The queue

`/manage/` reads applications back through the registry's `listRequests` query
(`MembershipRegistry.fetch_applications`) and lists **only the ones still
awaiting a decision** — see `views._applications`.

- **An application record is permanent, so "everyone who has applied" is not a
  queue.** The record reads identically whether its author was approved,
  refused, or never looked at, and it stays on file afterwards; listing all of
  them made this panel a second copy of the member table below it.
- **Whether one has been answered is settled by time, not by presence.** A DID
  having a `MembershipCache` row means somebody decided *once* — not that the
  record on file now has been decided. A revoked member who applies again writes
  a fresh record at the same rkey, so "has a cache row, therefore handled" would
  drop exactly the person asking to come back. A row is still waiting when there
  is no membership event for that DID, **or** when the application post-dates
  the last one; the latter is flagged *asked again*, because readmitting someone
  is a different decision from admitting a stranger.
- **What is left out is counted, never silently dropped** — the same posture as
  the unreadable count, so the queue can be short without anything going
  missing.

- **This is the one collection Corliss may read from the firehose index**, and
  the exception is not a softening of the rule above it. Grants must come from
  the space because the grant lexicon is published and anyone can write one
  into their own repo; an application is *self-authored by definition*, asserts
  only "I would like in", and is worth nothing until an admin writes a grant. So
  reading it from the index is reading exactly what it claims to be.
- **It needs no credential** — only `MEMBERSHIP_REGISTRY_URL`. `listRequests`
  is a query over records that are already public, so it deliberately does not
  require `MEMBERSHIP_REGISTRY_TOKEN`, and never sends it: a token in a URL is a
  token in a log, and this endpoint has no use for one.
- **The state column comes from `MembershipCache`, never from the
  application.** The record reads identically whether its author was approved,
  refused, or never looked at — only the cache knows which.
- **A record that cannot be read is counted, not dropped.** The failure this
  panel exists to prevent is somebody asking and the console not showing it, so
  an unparseable row is rendered as a number rather than as an absence. A
  registry that cannot be reached renders as a failure, never as an empty queue.

#### Deciding — approve, tier change, revoke

Each waiting row carries a tier and an **Approve**; each member row carries a
tier and **Set tier**, plus **Revoke**. All three go to the registry as
`admin.approveMember` / `admin.revokeMember` (`MembershipRegistry.approve` and
`.revoke`).

- **A tier change is an approval.** There is no third call and there should not
  be one: re-approving writes a fresh grant and latest-event-wins resolves it,
  so a member row's button and an applicant's button are the same operation
  pointed at different people. Nothing is ever edited, and a revoked member's
  button reads *Readmit* because that is literally what submitting it does.
- **Revoking appends.** The grant it answers stays exactly where it was — the
  space is append-only, and a member is active iff there is a grant with no
  later revocation.
- **The write is authored by the admin, not by Corliss.** It travels as their
  own access token with a DPoP proof signed by a key the registry provisioned
  during their login, so `caller_did` is them and the runtime stamps them as the
  author. There is deliberately no Corliss credential that could do this: a
  procedure needs a proof, and no shared token can produce one. That is the same
  asymmetry that lets `syncMembers` be a read-only query with a bearer token.
- **The roster is checked twice and both are load-bearing.** `is_cluster_admin`
  gets the admin onto the page; the Lua re-reads the roster on every write and
  refuses a caller who is not on it. The near check is ergonomics — a stale
  roster shows a refusal instead of a 500 — and the far one is the authority.
- **Nothing here writes `MembershipCache`.** The registry pushes the event back
  to `/membership/events` after the space write, so the tables lag a decision by
  that round trip, and clicking approve twice writes a redundant grant rather
  than doing damage.
- **It needs a registry session, which only an admin's login picks up** — see
  [Signing in as an admin](#signing-in-as-an-admin). Without one the controls
  render disabled with the reason rather than failing at the click.

Roster editing is the one thing still left to the Manage Console.

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
reason — it keeps the token out of any edge or CDN log, and keeps the run from
depending on public DNS.

Doing so needs `MEMBERSHIP_REGISTRY_HOST` as well: the registry routes by virtual
host and answers HTTP 421 "Unknown host" to a request whose `Host` is a bare IP.
A reverse proxy normally preserves the public name on the way through, so
bypassing the proxy means presenting it yourself. Leave it blank when the URL is
already the public origin. It is deliberately a
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

Not built yet: the systemd timer and the run at boot. A real production run has
since reported clean, so what remains is wiring rather than a precondition —
`manage.py reconcile_membership` already exits non-zero on an incomplete report,
which is what lets a scheduled run fail loudly instead of logging success over a
half-empty cache.

### Signing in as an admin

An admin's login is a **different login from the first network call onwards**,
and it has to be, because of one constraint at the registry: it provisions the
DPoP key that a session's tokens must be bound to. `POST /oauth/dpop-keys`
returns a private JWK, and the handshake is expected to have been run with it
before the tokens come back at `POST /oauth/sessions`. So a key chosen after the
token exchange is too late — the tokens are already bound to something the
registry has never seen. Corliss cannot adopt the tokens it already holds.

`views._dpop_key_for` is where that forks. It asks `is_cluster_admin` — a cached
read of a public record, no session needed — and for a current admin provisions
the key from the registry instead of minting an ephemeral one. `callback` then
registers the session and stamps `AtprotoToken.registry_session_at`.

Four things worth holding onto:

- **The decision is made on the *unverified* pre-resolved DID**, which is the
  opposite of the rule `callback` follows for the DID it keys on. That rule
  decides *who someone is*; this decides only which key to generate. Guess wrong
  and the cost is a session nobody can use, because the Lua re-reads the roster
  on every write.
- **A registry outage means no approvals, never no login.** Provisioning failure
  falls back to the ephemeral key and the login completes; the admin lands on
  `/manage/` with the controls disabled and the reason, and the failure is a
  `registry key provision failed` line in the log. Making this unconditional
  would turn a registry outage into a total login outage.
- **Non-admin logins are untouched**, and the registry never sees a non-admin's
  tokens.
- **Nothing new is stored to make the write work.** For an admin,
  `dpop_private_pem` simply *is* the registry's key, so one key pair serves both
  the member's own PDS and the registry, and `atproto.write_record`'s refresh
  path works on it unchanged. `registry_session_at` exists only so the console
  can offer a disabled button with a reason.

Corliss is a **public** client here, as the SPA is: a client key
(`MEMBERSHIP_REGISTRY_CLIENT_KEY`, which reads do not require but writes do) and
a PKCE verifier binding the provisioning to the registration. That verifier is a
*second* one, for a different server than the PDS OAuth's, and the two are named
apart because confusing them would be silent.

**The proof names the public origin, not the address dialled.** Corliss reaches
the registry internally while presenting the public `Host`; the registry rebuilds
the request URI from that header and compares it to the proof's `htu`. Signing
the internal address earns `401 DPoP proof htu mismatch` on every write — the
same internal-address-with-a-public-name trap as the HTTP 421 in
[Reconciliation](#reconciliation--rebuilding-the-cache-from-the-registry). See
`MembershipRegistry.public_url`.

### GATE — where membership is actually enforced

Signing in is not the same as being let in. Anyone with an atproto handle can
complete a login here; `membership.may_enter(did)` is the single question that
decides whether they may use the cluster, and it has two answers that pass:

- an **active grant** in the cache — what membership means; or
- a **current place on the admin roster** — which needs no cache row at all.

**The second clause is what makes closing the gate survivable.** A Corliss
rebuilt from nothing has an empty cache and therefore every member locked out —
including every admin, if the gate asked only the cache. The roster is a public
record read straight from the service DID's repo, so an admin can still get in
and press the button that refills the cache. Gating on the cache alone would
make the recovery path depend on the very thing being recovered.

It buys that admin nothing else. Entitlements — the tier an `id_token` will
carry — come from `membership_for`, so an admin with no grant enters Corliss and
receives nothing they were never granted. **GATE-for-Corliss and
ENTITLE-for-Open-WebUI stay two questions**, which is also how "admin does not
imply member" is answered without inventing a grant.

Four surfaces ask, and `require_membership` in `corliss/views.py` is the only
thing that asks:

| Surface | Why it is gated |
| ------- | --------------- |
| `/oidc/authorize` | **the one that matters.** The handoff into Open WebUI, reached on *every* exchange — so it is the only place that can refuse a session established before the gate existed, or one whose owner has been revoked since they signed in. Gating login alone is a gate with a hole in it |
| the login resume | GATE applies to the **resume, not the login**. A non-member still gets a session — they need one to apply — but not a ride onward into the relying party they came from |
| `/api/` | gated before it grows a real "create key" button |

Two surfaces must **never** be gated, which is why this is a per-view helper and
not middleware — middleware covers everything by default, and these would have
to be remembered as exemptions:

- **`/admin/login/`** — `ensure_admin`'s break-glass account (`did:local:admin`)
  is not on the roster and will never have a cache row. A gate across Django's
  own login locks out the one door that is supposed to work when nothing else
  does.
- **`/manage/`** — gated on the roster, no database, precisely so it opens when
  the cache is empty. It holds the reconcile button.

`/` is gated by neither: it is where every refusal *lands*. Its
signed-in-but-not-a-member state is the gate's user-facing form and the only
place membership can be asked for, so `authorize` refuses to there rather than
returning an OIDC `error=access_denied` to the relying party — a deliberate
deviation, because the spec-shaped answer leaves the person inside Open WebUI
reading a generic failure with nowhere to go.

**The nav shows the gated surfaces to a non-member and opens neither.** Chat and
API render as disabled entries on the same `may_enter` condition the pages
enforce, so the row does not reflow when someone is let in. Both alternatives
were worse in opposite directions: hiding them left a non-member with no idea
what membership is *for* — the home page explains the refusal, but the nav is
where the cluster says what it has — while a live link is a promise broken on
the next click, which is exactly what Chat used to be. They are `<span>`s rather
than `<a>`s without an `href`, so there is nothing to click, focus, or
middle-click into a tab. Chat still vanishes entirely when `CHAT_URL` is unset:
a closed door says "not for you yet", which on a cluster with no chat deployed
would be a different statement, and a false one.

**A cache miss never reaches the registry.** The gate reads the cache and the
roster and nothing else; reconciliation is an operator action and a scheduled
job, never a step in somebody's login.

**Where the gate stopped, and how far past it now reaches.** "Reached on every
exchange" means every *OIDC* exchange — and a relying party performs one only
when it has no valid session of its own. Open WebUI mints its own JWT after the
handoff and authenticates from that, so Corliss is not asked again until it
expires. That left two holes GATE could not reach from its own side: revoking a
member did not end their chat session, and signing out of Corliss did not sign
them out of chat.

**Back-channel logout closes both** — see below. What it does *not* do is make
the gate self-sufficient, and the distinction is the thing to hold onto: it is a
message Corliss sends, so it works exactly as well as the delivery does. The
relying party's own token lifetime is still the bound that holds when the
message doesn't arrive, and it is deliberately kept short (4h on this cluster)
rather than relaxed now that this exists.

### Back-channel logout — ending a session, not waiting it out

`corliss.oidc` mints a `logout_token` (RS256, the same key and the same JWKS as
the `id_token`, so an RP that can validate one validates the other with no extra
configuration) and POSTs it to the relying party's back-channel endpoint. Three
things trigger it:

| Trigger | What it fixes |
| ------- | ------------- |
| `views.logout` | signing out of Corliss now ends the chat session too |
| a revoke reaching `membership.apply_event` | **the point of the whole thing** — revocation goes from "within the RP's token lifetime" to seconds |
| `reconcile` deactivating someone | free, because reconcile's pass 2 applies events through `apply_event` — one trigger, both routes into the cache |

**Who gets told is decided by the registered relying parties, not by
`OidcSession`.** Corliss does keep a session record — one row per (member,
relying party), written at token *redemption*, not at `authorize`, because a
code can expire unredeemed and the RP has no session until it trades one in.
But that row is an optimisation and an audit trail, never a precondition for
sending.

That distinction is not decoration; it was a bug in the first cut of v0.6.0.
Rows only start existing the moment the feature ships, so gating delivery on
one made sign-out and revocation silent no-ops for every session that *already*
existed — which, on deploy day, is all of them. It is the same trap GATE had to
avoid by enforcing at `/oidc/authorize` rather than at login, and it takes the
same answer: act on what is always true (the RP is registered, and we know the
member's `sub`) rather than on a record that only exists going forward. The row
supplies `sid` when we have one; the RP's own lookup by `sub` does the work when
we don't.

Five properties worth stating, because each has a plausible wrong answer:

- **A member with no session record is still notified.** See above — this is
  what makes the feature work on the sessions that predate it.
- **A notification never fails its caller.** Every trigger is something that
  already happened and cannot be undone — a member signed out, the registry
  recorded a revocation. Failing the sign-out because a chat server was
  unreachable would break a working thing to report a broken one.
- **Only a *live* membership ending notifies.** A revoke landing on a DID with
  no active row revokes nothing. That is not a corner case: it is what reconcile
  does on a rebuilt cluster, replaying every winning event into an empty cache,
  where past revocations are many people's winner. The recovery path stays
  quiet.
- **A dry run notifies nobody**, because `reconcile --dry-run` goes through
  `_would_change` rather than `apply_event`. A preview must not sign anyone out
  to show an operator what a run would do.
- **The return leg is not internal, and cannot be made so.** Corliss POSTs to
  the RP's internal address, but the RP validates what it receives by fetching
  our discovery document and the `jwks_uri` inside it — both the *public*
  origin, because the issuer must be the public one or `iss` won't match. So
  delivery still depends on the edge. One more reason the short expiry stays.

## API keys — `/api/`

Members reach the cluster's models directly over HTTP, with a key they issue
themselves. Corliss holds the credential that mints those keys; the page shows
each secret exactly once.

This is the half of the deploy plan's Phase E that moves LiteLLM provisioning
out of the registry. It was HappyView Lua until the registry was stripped of its
gateway integration (member-registry `ad9b424`, "Phase E0"), which was right —
a registry that provisions nothing needs no credential that can act on anyone's
behalf — and left nothing provisioning LiteLLM until this.

### Settings

| Setting | Meaning |
| ------- | ------- |
| `LITELLM_URL` | Where **Corliss** reaches LiteLLM. The **internal** address (`http://10.1.1.<ctid>:4000`), not `API_URL`. |
| `LITELLM_PROVISIONER_KEY` | A `proxy_admin` virtual key, **not** the LiteLLM master key. |
| `LITELLM_MAX_KEYS_PER_MEMBER` | How many keys one member may hold (default 5). LiteLLM enforces no limit of its own. |

Either of the first two blank leaves `/api/` saying it is not configured, the
same posture the registry settings take. Nothing 500s because an integration is
absent.

**`LITELLM_URL` is not `API_URL`, and conflating them breaks this quietly.**
`API_URL` is the public origin a *member* points their client at. `LITELLM_URL`
is a service-to-service call between two CTs on one bridge — and server-side
Python **cannot** fetch our own public origin, because Cloudflare's Browser
Integrity Check refuses non-browser user agents with `error code: 1010`. That is
the defect that shipped back-channel logout fully built and completely inert; it
is set for this call too.

### What is stored

**Nothing.** LiteLLM is the source of truth for keys. `/api/` calls `/key/list`
on every render, so a key revoked from `zai-litellm-key` is gone from the page
too. The plaintext exists for exactly one render — the view pops it out of the
session as it draws — and Corliss never writes it anywhere. A stored key would
be a credential in a second place for no gain: it cannot be re-shown, and
LiteLLM already knows every fact about it worth reading.

### The rules that make a shared provisioner key safe

The provisioner key can mint and delete keys for *anyone*, so every operation
re-establishes on the server who is asking rather than trusting the request:

- **The LiteLLM `user_id` IS the member's DID.** Not a handle, not a hash. That
  is what makes `/user/new` idempotent on retry, which is what lets a page load,
  a push and `sync_litellm` all provision without coordinating.
- **Issuance proves an active grant; revocation proves ownership.** The token in
  the revoke form arrives from the client, so it is looked up in *that DID's* key
  list before anything is deleted.
- **GATE is not the entitlement question.** A roster admin passes GATE and
  reaches this page — that is the recovery path — and still gets no key, because
  the tier comes from `MembershipCache` and they have no grant.
- **A tierless membership cannot mint a key, and that is a security check.** A
  key with no team inherits every model, so an unscoped key is *more* permissive
  than any tier. The five pre-E0 grants in the production space carry no tier;
  their holders exist in LiteLLM and are refused a key until one is set.
- **The key list is filtered by `user_id` twice** — once as a query parameter,
  once over the response. Handing one member another's keys would be this
  module's worst failure and the second check costs one comparison.

### Tiers are LiteLLM teams

A grant's tier slug (`level-0` … `level-9`) maps to a LiteLLM **team**, resolved
at runtime by `team_alias`. The teams are created by the zai-ops `litellm` role;
Corliss looks them up rather than holding a team id, because an id is generated
at creation and would have to be carried out of Ansible by hand.

Model access and per-member limits live on the team, so changing someone's tier
is a team move — and **a tier change ends the member's existing keys.**

That is not a design preference. LiteLLM refuses to move an existing key between
teams: `/key/update` with a new `team_id` answers **403** and the key does not
move (probed against the deployed proxy, 2026-08-19). A key's access is fixed at
the team it was minted against, so the only way a tier change can take effect is
to delete what predates it — `litellm.prune_foreign_keys`, called from
`apply_event` and again by `sync_litellm`.

Leaving them is the unsafe direction: a member moved *down* a tier would keep
the access they just lost, silently and for as long as the key lives. The rule
applies to upgrades too, uniformly, because one that deletes on the way down but
not on the way up is unpredictable — and the alternative on the way up is an
upgrade that visibly does nothing. `/api/` says so above the key table.

Pruning is keyed on the team, not on "did the tier change", which the hook has
no way to know. A key already on the right team is left alone, which is what
keeps a reconcile replay on a rebuilt cluster quiet.

### Revocation reaches LiteLLM

The same `apply_event` hook that ends a chat session ends API access, for the
same reason: GATE decides who may *start*, and neither a chat JWT nor an API key
stops by itself. Keys are deleted first, then the team membership — if the second
half fails the member has already lost access and a retry only finishes the
paperwork.

Both notifications are best effort and neither may swallow the other. They also
must not fail the push: the grant already happened in the registry, so raising
here would report a failure for something that succeeded.

### `manage.py sync_litellm`

The repair for what the push is allowed to drop.

```bash
manage.py sync_litellm --dry-run
manage.py sync_litellm
```

Walks `MembershipCache`, ensures every active member exists in LiteLLM in their
tier's team, and deletes keys still held by revoked ones. **Exits non-zero when
anything could not be aligned** — a member missing from LiteLLM accrues no spend
and reads as working from every direction, so a run that reported success over
one would hide exactly the state it exists to find.

Reads the cache, never the registry, which keeps the two repairs separable. On a
rebuilt cluster run `reconcile_membership` first: that re-derives the cache from
the registry, this re-derives LiteLLM from the cache.

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

`MembershipCache` is also visible in the Django admin, **read-only** — no add,
no change, no delete, not even for a superuser. The table is a cached
computation over the registry's events, so an edit there is either reverted by
the next push or, until then, a membership no record backs. Removing an orphan
stays a deliberate act, taken with the console's orphan report in hand.

The admin table lists only the terms in force **now**, one row per DID. Departed
terms are not shown and not lost: they stay in the record, where
`Roster.was_admin_at` reads them when a past grant's authority is being judged.
The tables show handles, resolved from the `User` row where the member has
signed in and from the DID document otherwise (`membership.handles_for`), with
the DID on each cell's `title`. That resolution is **display only** — handles are
mutable, so nothing may key, compare, or store what comes out of it, and a
lookup that fails renders the DID rather than an error.

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
ENABLE_OAUTH_BACKCHANNEL_LOGOUT=true             # exposes POST /oauth/backchannel-logout
REDIS_URL=redis://…                              # required, or the RP cannot revoke its own JWTs
```

Register the RP's redirect URI in Corliss's `OIDC_REDIRECT_URIS`
(e.g. `https://chat.example.com/oauth/oidc/callback`), and its back-channel
logout endpoint in `OIDC_BACKCHANNEL_LOGOUT_URI` — its *internal* address, since
that call is service-to-service and has no business routing out through public
DNS and back in through the edge.

**Redis is not optional on the RP side, and not merely for logout.** Open WebUI
can drop stored OAuth sessions without it, but revoking an already-issued JWT is
what makes a logout token mean anything, and that needs the revocation store. Be
deliberate about it: once `REDIS_URL` is set, Open WebUI consults Redis on
*every* authenticated request, so Redis being unreachable takes chat down rather
than degrading it. See zai-ops' `docs/roles/redis.md` for the full shape of that
trade.

**`id_token` claims:** `sub` = DID, `handle` (also `preferred_username`),
`iss`/`aud`/`exp`/`iat`/`nonce`, `sid` (the `OidcSession` a later `logout_token`
will name), plus `email` + `email_verified` when the member's PDS supplied one.
Email is best-effort — sourced at login via the `transition:email` scope and
`com.atproto.server.getSession` — so a member who declines the scope simply gets
no `email` claim. DID is the only stable identifier; never key on handle or
email.

**`logout_token` claims:** `iss`/`aud`/`sub`/`iat`/`jti`/`sid`, plus the
`events` claim naming `http://schemas.openid.net/event/backchannel-logout`. No
`nonce` — the spec forbids one and relying parties reject a token that carries
it.

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
