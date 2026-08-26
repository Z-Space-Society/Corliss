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
[Membership](docs/membership.md).

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
in its Manage menu (**on its way out** — `/manage/` now covers everything that
console did, including roster editing; the link and this setting go when the
`manage_console` role is removed), and `API_URL` both the endpoint shown on
`/api/` and the
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

The nav's admin links answer to **one authority**: the atproto admin roster
(`user.is_cluster_admin`). Making someone an admin writes the roster entry *and*
sets Django's `is_staff`, from one operation — `manage.py make_admin`, or the
button on `/manage/`. The roster is the authority and `is_staff` is a mirror of
it, re-derived at every login so the two cannot drift.

`is_superuser` is **not** part of that. It bypasses every permission check, so
`--superuser` has to be asked for by name; plain `is_staff` opens the admin index
with no model permissions at all, which is what made merging it affordable. See
[Membership](docs/membership.md).

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

- **The handle you type is lowercased first, because handles are
  case-insensitive and DIDs are not.** Without that, `Jacob.example` and
  `jacob.example` mint two different `did:dev:` DIDs and therefore two member
  rows for one person, of which only one spelling matches `DEV_ADMIN_DIDS`. A
  real login cannot drift this way: resolving a handle returns one canonical
  DID however the handle was spelled.

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

Write the handle part in lowercase — the comparison is an exact string match,
as DID comparison must be, and the dev sign-in mints lowercase.

Those DIDs answer yes to `is_cluster_admin` and to nothing else: no membership,
and no grant. Same `DEBUG` requirement and the same `manage.py check` failure if
it is set without one. Note it is a *read* override, not a roster write — it
makes the check answer yes without a record existing, so it does not go through
`appoint_admin` and sets no `is_staff`.

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

Every page footer carries a build stamp — `Corliss v0.8.3`, linking the repo and
that tag — so the running version is readable off the site itself. It comes from
`git describe --tags --always --dirty` against the checkout
([`corliss/version.py`](corliss/version.py)), falling back to
`pyproject.toml`'s `version` where there is no `.git`. A checkout past its tag
reads `v0.8.3-3-gabc1234` and links the commit; a dirty tree says so and links
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
manage.py make_admin alice.bsky.social   # cluster admin: roster entry + is_staff.
                                         #   --remove reverses it; --superuser opts in
                                         #   to the flag that bypasses every check.
                                         #   Needs the service account's session.
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
| Console — applications, members, admins, invite, reconcile (cluster admins) | `/manage/` |
| Authenticate the service account so roster edits can be made (POST, cluster admins; returns through `/auth/callback`) | `/manage/unlock` |
| Systems — the stack, status stubbed (cluster admins) | `/systems/` |
| Django admin | `/admin/` |

Discovery and JWKS sit at the root deliberately: an OIDC issuer of
`https://example.com` must serve its discovery document at
`https://example.com/.well-known/openid-configuration`.

## Membership — who is allowed in

Corliss authenticates people; it does not decide who may use the cluster. That
lives in an external registry (append-only grant and revocation records, held in
a HappyView space). Corliss keeps a **cache** of the registry's answer in
`MembershipCache`, and the registry is authoritative in every disagreement.

Three properties carry the whole design, and each is load-bearing:

- **Membership is derived, never stored as truth.** Grants and revocations are
  append-only events; "is a member" is latest-event-wins over them, and any
  stored copy is a cache that `reconcile` can rebuild from scratch.
- **The registry pushes; nothing on the request path ever pulls.** A cache miss
  is a **no**, never a lookup — which is what keeps a registry outage from
  becoming a login outage.
- **Signing in is not being let in.** GATE is a separate question from
  authentication, enforced at `/oidc/authorize` rather than at login.

**→ [`docs/membership.md`](docs/membership.md)** covers all of it: the push
envelope, applying and the admin queue, deciding, reconciliation, why an admin's
login differs from the first network call onwards, GATE, and back-channel logout.

## API keys — `/api/`

Members reach the cluster's models directly over HTTP, with a key they issue
themselves. Corliss holds the credential that mints those keys; the page shows
each secret exactly once.

Provisioning lives here rather than in the registry because a registry that
provisions nothing needs no credential that can act on anyone's behalf.

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
  than any tier. Such a member exists in LiteLLM and is refused a key until a
  tier is set.
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
applications are read live from the registry's index and are written by the
applicants themselves; members are Corliss's own cache, which can be stale,
incomplete, or orphaned. Reconciliation is what makes the second agree with the
registry.

`MembershipCache` is also visible in the Django admin, **read-only** — no add,
no change, no delete, not even for a superuser. The table is a cached
computation over the registry's events, so an edit there is either reverted by
the next push or, until then, a membership no record backs. Removing an orphan
stays a deliberate act, taken with the console's orphan report in hand.

**One table, current members only.** A revoked person is history and the registry
is where history lives; re-inviting the same handle readmits them, which is what
readmission always was. Members are shown by handle with the DID on the cell's
`title` — a DID is never text. `membership.ensure_user` records the handle when a
grant is written, so a member is named from the moment they are admitted rather
than from their first sign-in. That resolution is **display only**: handles are
mutable, so nothing may key, compare, or store what comes out of it.

There is no separate admins table. **Admins are members**, enforced when one is
appointed, so admin is a column and `Make Admin` / `Revoke Admin` sit on the
member's own row. The column renders from Django's `is_staff` — a local mirror
re-derived at every login — while the registry's roster record stays the
authority. The service account holds no grant and so never appears here: it is
infrastructure, not a person. Revoking a member who is an admin ends their admin
authority first, then their membership; that order is the one whose half-done
state is safe.

This page **replaces** the separate SPA admin console — approve, revoke, set
tier, invite, and roster editing all happen here. Approve, revoke and set tier
are writes to the registry space and keep requiring a current-admin caller, so
`MEMBERSHIP_REGISTRY_TOKEN` must never gain write scope.

Roster editing works differently, because it has to. The roster is a record in
the service account's own repo and an atproto repo is writable only by its owner,
so the acting admin cannot write it: Corliss checks that *you* are a current
admin, then makes the write with the service account's session, recording you as
`addedBy` / `removedBy`. **You never sign in as it and nobody is handed a
password.** The lock in the Members card's corner runs an ordinary atproto handshake —
you authenticate at the service account's own PDS and land back on `/manage/`
still signed in as yourself. An app password would not do: HappyView verifies the
tokens handed to `/oauth/sessions` against the DPoP key it provisioned, so a
Bearer token can never produce a session able to grant registry space access —
and without that half, a new admin is on the list and cannot approve anyone.

Appointing is two writes. The roster write goes first, so a failure changes
nothing; the space-access half is reported rather than raised, and re-running the
same action finishes it. Both halves are idempotent. A lapsed service session
degrades **only** roster editing — approve, revoke, login and every member-facing
page run on the admins' own sessions — and the lock shows its health so a lapse
is found before somebody needs it.

Two edits are refused outright: removing the last current admin, and removing the
service account. The first would end every approve and revoke with no way back;
the second removes the identity that performs these writes.

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
