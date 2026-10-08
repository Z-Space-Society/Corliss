# 0001 Spec: Multi-client OAuth and "Your vaults"

Status: draft, 2026-10-07.

## Goal

Corliss serves one relying party today, Open WebUI. This spec makes it a
general OAuth provider for public clients, so that Claude, Claude Code and the
scn-obsidian plugin can obtain tokens that scn-sync-relay accepts, and adds a
page where a member sees their vaults.

1. Public clients identified by a Client ID Metadata Document (CIMD), with
   PKCE, refresh tokens and audience-bound access tokens.
2. A members-only Obsidian page: what the service is, how to connect
   Obsidian and Claude, the member's vaults, and a way to create one. The
   vaults live on the relay.

The rule for all of it: access works while you are an SCN member and stops
when you are not.

The work is labelled C1 to C7:

| Label | Change |
|---|---|
| C1 | Client model: a lookup in place of the single `OIDC_CLIENT_ID` comparison |
| C2 | CIMD: fetch, validate and cache client metadata documents |
| C3 | PKCE with S256 for public clients |
| C4 | Redirect URI matching: exact, loopback without the port, custom scheme |
| C5 | Refresh tokens: rotation, reuse rule, membership check on every use |
| C6 | Access tokens for SCN resources, audience from the `resource` parameter |
| C7 | Obsidian page: setup instructions, the member's vaults, create a vault |

## Non-goals

- Dynamic client registration. CIMD covers every client here.
- Anthropic-held client credentials. That is for directory listings.
- Any change to Open WebUI's flow, its ID token or its back-channel logout.
- Any change to `atproto.SCOPE`. Changing it forces every member to consent
  again at their PDS.
- Signing key rotation. One RSA key, as today.
- Token introspection or a revocation endpoint.
- Sharing.
- Renaming or deleting a vault.
- Storing anything about vaults in Corliss. Corliss asks the relay to
  create a vault and to list them; the relay holds the records.

## Current state (v1.3.4)

- **One client.** `authorize` compares `client_id` and `redirect_uri` against
  `OIDC_CLIENT_ID` and `OIDC_REDIRECT_URIS` (`corliss/views.py:2002-2005`).
  `token` compares the ID and secret against settings
  (`corliss/views.py:2122-2123`). `oidc.registered_logout_endpoints` returns
  the same single client (`corliss/oidc.py:262`).
- **Confidential only.** `token` authenticates the client before it reads
  `grant_type` (`corliss/views.py:2120-2128`), so a client with no secret is
  refused with `invalid_client`.
- **`openid` is required** at `authorize` (`corliss/views.py:2008-2009`).
- **No consent screen.** A signed-in member is redirected with a code
  immediately (`corliss/views.py:2038-2048`).
- **The access token is the ID token** (`corliss/views.py:2162`), audience
  `client_id`, valid one hour (`corliss/oidc.py:36,119`).
- **`sub` is already the DID** (`corliss/oidc.py:118`).
- **One RSA key.** `kid` is the key's RFC 7638 thumbprint and
  `signing.sign_rs256` sets it in the header (`corliss/signing.py:74-97,
  129-134`). The JWKS publishes that key and the ES256 atproto key
  (`corliss/signing.py:116-118`).
- **Sign-in round trip.** An anonymous `authorize` stores
  `request.get_full_path()` in the session and redirects to login
  (`corliss/views.py:196-206,2019-2020`). After the atproto callback,
  `_resume_after_login` sends the browser back to that path
  (`corliss/views.py:278-293`). The whole query string survives, so
  `client_id`, `redirect_uri`, `state`, `code_challenge` and `resource` need no
  new carrier.
- **Membership gate** at `authorize`, through `membership_denial`
  (`corliss/views.py:2034-2036`), which asks `membership.may_enter(did)`
  (`corliss/membership.py:585-615`).
- **Stored state.** `OidcAuthCode` holds code, user, client, redirect, nonce
  and scope (`corliss/models.py:258-280`). There is no PKCE challenge, no
  resource, no refresh token, no client record and no consent record.
  `redirect_uri` is a `URLField`, 200 characters. Expired codes are never
  deleted.
- **Discovery.** Only `/.well-known/openid-configuration`
  (`corliss/urls.py:41-45`).
- **Latent fault.** `OIDC_CLIENT_SECRET` defaults to an empty string
  (`corliss/settings.py:75`), and `token` compares the presented secret, or
  `""` when none is sent, against it. A deployment with no secret configured
  accepts `client_id=open-webui` with no secret. Production sets one. Fixed
  under C1.

## Clients

| Client | Kind | `client_id` | Redirect URI | Match |
|---|---|---|---|---|
| Open WebUI | confidential | `open-webui` (`OIDC_CLIENT_ID`) | `OIDC_REDIRECT_URIS` | exact, unchanged |
| Claude web, iOS, Desktop | public, CIMD | a document Anthropic hosts under `https://claude.ai` | `https://claude.ai/api/mcp/auth_callback` | exact |
| Claude Code | public, CIMD | `https://claude.ai/oauth/claude-code-client-metadata` | `http://localhost:<port>/callback`, `http://127.0.0.1:<port>/callback` | loopback, port ignored |
| scn-obsidian plugin | public, CIMD hosted by Corliss | `<PUBLIC_BASE_URL>/clients/scn-obsidian.json` | `obsidian://scn-obsidian` | exact |

Claude Code's document declares `http://localhost/callback` and
`http://127.0.0.1/callback` with no port, and grant types
`authorization_code` and `refresh_token`.

The plugin is one client on every platform. Obsidian on desktop and on iOS
send the same `client_id` and the same redirect URI, which Obsidian hands to
the plugin's protocol handler. The plugin asks for `offline_access` and the
sync resource.

The exact `client_id` URL the hosted Claude apps send is not published. See
open question 1.

## Token contract

This is what the relay verifies, and therefore what Corliss must issue to a
public client. It is a contract: a change here is a change to the relay.

Access token, a JWT:

| Part | Value |
|---|---|
| Header `alg` | `RS256` |
| Header `kid` | The OIDC key's thumbprint, as published in the JWKS |
| Header `typ` | `at+jwt` |
| `iss` | `PUBLIC_BASE_URL`, no trailing slash. Same issuer as the ID token. |
| `sub` | The member's DID |
| `aud` | One resource URL, as configured in `OIDC_RESOURCES`. A string, not a list. |
| `exp` | `iat` + 900 seconds |
| `iat` | Issue time |
| `jti` | Random, unique per token |
| `scope` | The granted scope, space separated. May be empty. |
| `client_id` | The client the token was issued to |

- No handle, name or email. The plugin sends this token in a websocket URL, so
  it carries nothing that identifies a person beyond the DID.
- The JWKS contains two keys of different types. A verifier selects by `kid`
  and accepts RS256 only.
- The plugin uses the sync audience for both the websocket and the relay's
  `/vaults` endpoints. An MCP client uses the MCP audience.
- The relay closes a sync connection at `exp`. The refresh grant is what keeps
  a member connected and what cuts a removed member off.
- The relay calls nothing on Corliss except the JWKS URL.

ID tokens are unchanged, and are issued to a public client only when `openid`
is in the granted scope. An ID token's `aud` is the `client_id`, never a
resource URL, so the relay cannot mistake one for an access token.

## C1. Client model

`oidc.resolve_client(client_id)` replaces the two settings comparisons. It
returns a small value object: `client_id`, `kind` (confidential or public),
`redirect_uris`, `name`, and `host` (the host of the `client_id` URL, blank
for Open WebUI).

- `client_id == settings.OIDC_CLIENT_ID`: the confidential client, built from
  settings exactly as today.
- `client_id` is an `https://` URL: a public client, resolved under C2.
- Anything else: `unauthorized_client`, as today.

No table of clients. Open WebUI stays in settings, and public clients are
described by their documents.

Per kind:

| | Confidential (Open WebUI) | Public |
|---|---|---|
| Token endpoint auth | secret, post or basic | none |
| PKCE | not checked, as today | required, S256 |
| `openid` scope | required, as today | optional |
| `resource` | ignored | required |
| Grants | `authorization_code` | `authorization_code`, `refresh_token` |
| Token response | ID token as both tokens, as today | access token, plus refresh and ID token by scope |
| Consent screen | none, as today | yes |
| `OidcSession` row | yes, as today | no |

Public clients record no `OidcSession`. That row exists to carry `sid` for
back-channel logout, and a public client has no logout endpoint to notify.

**Fix.** `token` refuses the confidential client with `invalid_client` when
`OIDC_CLIENT_SECRET` is blank. With `none` advertised in discovery, the empty
comparison described under Current state must not stand.

## C2. Client ID Metadata Documents

### Which URLs are accepted

`OIDC_CLIENT_METADATA_ALLOWLIST` is a list. Each entry is one of:

- an exact `client_id` URL, or
- an origin (`https://claude.ai`), which accepts any `client_id` on exactly
  that scheme, host and port. Compared on parsed components, never by string
  prefix.

Corliss's own documents are always accepted and need no entry. A `client_id`
URL that matches nothing is refused with `unauthorized_client` before any
fetch. An empty list therefore means only the plugin can sign in.

The allowlist check runs first because `authorize` validates the client
before it asks for login (`corliss/views.py:2001-2020`). Without it, an
anonymous request could make Corliss fetch any URL.

### Corliss's own document

`GET /clients/scn-obsidian.json` serves:

```json
{
  "client_id": "<PUBLIC_BASE_URL>/clients/scn-obsidian.json",
  "client_name": "SCN Sync",
  "client_uri": "<PUBLIC_BASE_URL>",
  "redirect_uris": ["obsidian://scn-obsidian"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Built by a function in `oidc.py`, the way `atproto.client_metadata()` builds
the atproto one. `resolve_client` reads that function directly for this
`client_id` and never fetches its own origin over HTTP: with two gunicorn
workers a self-fetch can wait on itself.

The path is part of the client's identity. Changing it makes a new client,
and every plugin install signs in again.

### Fetching someone else's document

One function in `oidc.py`, which already owns the provider's outbound HTTP.

- `https` only, with a path component. No userinfo, no fragment.
- Resolve the host first. Refuse loopback, private, link-local, unique-local,
  multicast and unspecified addresses, for every address the name resolves
  to. Connect to the address that was checked.
- No redirects (`allow_redirects=False`). A redirect is a failure.
- Timeout 5 seconds total. Read at most 64 KB, streamed, then stop.
- The response must be `200` with a JSON object body.
- The document's `client_id` must equal the URL exactly.
- `redirect_uris` must be a non-empty list of strings. `client_name` must be a
  string.
- `token_endpoint_auth_method`, when present, must be `none`.
- Each redirect URI must be `https`, or `http` on a loopback host. Any other
  scheme makes the whole document invalid. Custom schemes are accepted only
  from Corliss's own documents.

A fetch or validation failure is `invalid_client`, shown as an error page,
never a redirect.

### Caching

`OidcClientDocument` rows, keyed by `client_id`. The cache is the database
because Django's default cache here is per process, and there are two
workers.

- Fresh for 1 hour. `Cache-Control: max-age` shortens or lengthens that,
  clamped to between 5 minutes and 24 hours.
- A failed refetch serves the stale row for up to 24 hours and logs a
  warning.
- A failed first fetch is remembered for 60 seconds, so a broken URL cannot be
  used to make Corliss fetch in a loop.
- Only `authorize` fetches. The token endpoint never makes an outbound
  request: a code or refresh token already records the client it was issued
  to. This keeps the token endpoint inside Claude's 10 second limit.

## C3. PKCE

For public clients:

- `authorize` requires `code_challenge` and `code_challenge_method=S256`.
  A missing challenge, or `plain`, is `invalid_request`.
- The challenge is stored on the code.
- `token` requires `code_verifier`, 43 to 128 characters, and checks
  `BASE64URL(SHA256(verifier)) == challenge` in constant time. A mismatch is
  `invalid_grant`.

For Open WebUI, PKCE parameters are ignored as they are today.

## C4. Redirect URI matching

One function, given the requested URI and the client's list.

| Requested URI | Rule |
|---|---|
| `https://…` | Exact string match against the list |
| `http://` on `localhost`, `127.0.0.1` or `[::1]` | Match scheme, host, path and query against a list entry, ignoring the port on both sides |
| Custom scheme | Exact string match |
| Anything else | No match |

`localhost` and `127.0.0.1` are different hosts and do not match each other.
No match is `invalid_request`, shown as an error page, as today.

`OidcAuthCode.redirect_uri` stores the URI as requested, port included, and
`token` compares it exactly, as today.

**Redirecting to a custom scheme.** Django's `HttpResponseRedirect` refuses
any scheme outside `http`, `https` and `ftp`. The final redirect to a public
client uses a response class whose allowed schemes are exactly the scheme of
the already-validated redirect URI.

## Sign-in and consent

What a new client's user sees, in order:

1. **Request checks.** Client, redirect URI, `response_type`, PKCE, resource
   and scope are validated. An invalid client or redirect URI shows an error
   page. Once both are valid, any other failure goes back to a public client
   as a redirect with `error` and `state`. Open WebUI keeps today's JSON
   errors.
2. **Not signed in.** The request is stored in the session and the member
   signs in with their handle, exactly as today. A request whose path and
   query exceed 2048 characters is refused with `invalid_request` here,
   because the resume check would otherwise drop it silently and leave the
   member on the home page.
3. **Not a member.** Redirect to the home page, as today, for every client.
   That page explains the refusal and how to apply.
4. **Consent.** Public clients only. The screen shows:
   - the host of the `client_id` URL, as the name of the app asking. The
     document's `client_name` appears beside it as the app's own description
     and is never the headline, because it is self-asserted;
   - the host of the redirect URI;
   - for a loopback redirect, a plain statement that the sign-in will be
     handed to a program on this computer, and that the member should
     continue only if they started this from that program;
   - which resource is being opened, by its configured label;
   - the handle the member is signed in as;
   - Allow and Cancel.
5. **Allow** issues the code and redirects. **Cancel** redirects with
   `error=access_denied`.

Consent is a POST with CSRF protection. The validated request is held in the
session under a random ticket and the form posts only the ticket, so nothing
the browser sends at this step is trusted as request parameters. The
membership gate is asked again on the POST.

Remembering consent: an `OidcConsent` row per member, client and resource. A
client with an `https` or custom-scheme redirect skips the screen when a row
exists. A loopback client is asked every time, because any local program can
present another client's `client_id`.

Routes: `oidc/authorize` stays GET. The form posts to `oidc/consent`.

## C6. Access tokens and the resource parameter

`OIDC_RESOURCES` lists the resource URLs Corliss will issue tokens for: the
public sync URL and the public MCP URL.

Matching: lowercase the scheme and host, and drop a single trailing slash
from an otherwise empty path. Compare the result against each configured
entry treated the same way. The `aud` issued is the configured spelling, not
the client's.

At `authorize`, for a public client:

| `resource` | Result |
|---|---|
| Missing | `invalid_target` |
| Not in `OIDC_RESOURCES` | `invalid_target` |
| Sent more than once | `invalid_target`. One token, one audience. |
| Known | Stored on the code |

With `OIDC_RESOURCES` empty, every public authorization is refused with
`invalid_target`. An unconfigured deployment issues nothing.

At `token`, `resource` is optional. When present it must match the value
stored on the code or the refresh token, else `invalid_target`. When absent
the stored value is used.

For Open WebUI, `resource` is ignored and no resource access token is issued.

**Scopes.** `scopes_supported` gains `offline_access`. For a public client the
granted scope is the requested scope with unknown values dropped, and an
empty result is valid. The relay's protected resource metadata advertises no
scopes, so Claude may ask for `offline_access` alone.

Token response for a public client:

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "offline_access",
  "refresh_token": "<opaque, when offline_access was granted>",
  "id_token": "<jwt, when openid was granted>"
}
```

## C5. Refresh tokens

- Issued at code exchange when `offline_access` is in the granted scope.
- Opaque, from `secrets.token_urlsafe(48)`. Only the SHA-256 hash is stored.
- Bound to member, client, resource and scope. All tokens descended from one
  authorization share a `family`.
- Expire 30 days after issue. Each rotation starts a new 30 days, so a client
  in regular use never expires and an abandoned one does.

The `refresh_token` grant, in order:

1. Look up the hash. Unknown is `invalid_grant`.
2. `client_id` must equal the token's client. Otherwise `invalid_grant`.
3. **Reuse.** A token that was already used, or that was superseded, is a
   replay.
   - **Lost response.** If it was used no more than 60 seconds ago and no
     token issued from it has been used, the client is retrying after a
     response it never received. Mark the unused tokens issued from it as
     superseded and continue from step 4, issuing a new pair. iOS suspending
     Obsidian in the middle of a refresh is the ordinary case.
   - **Anything else:** delete the whole family and return `invalid_grant`.
     The member signs in again.
4. Expired is `invalid_grant`.
5. `resource`, when sent, must match. Otherwise `invalid_target`.
6. **Membership.** `membership.may_enter(did)`. If false, delete the family
   and return `invalid_grant`. This is the membership rule for every public
   client.
7. Claim the token with a conditional update, so that of two concurrent
   requests only one wins, the way codes are claimed today
   (`corliss/views.py:2145-2149`). The loser is handled as a replay under
   step 3, which inside the window gives it its own pair and supersedes the
   winner's.
8. Issue a new access token and a new refresh token in the same family, with
   the same resource and scope, in the same response.

A refresh token can only mint tokens for the resource it was issued for. A
member who uses both sync and MCP holds two refresh tokens.

A requested `scope` on refresh may narrow the access token and is otherwise
ignored. It never widens.

Every refusal on this grant is `invalid_grant` or `invalid_target`. Claude
treats any other code as a server fault.

### Membership freshness

`may_enter` reads `MembershipCache` and the admin roster and never asks the
registry (`corliss/membership.py:607-609`). That is what makes it safe to
call on a 30 second deadline, and it means the cache's staleness is the
bound on cutting a member off.

| Event | Access ends within |
|---|---|
| Revocation pushed by the registry and applied | 15 minutes: the life of the access token already issued |
| Push missed | The next reconcile run, plus 15 minutes |
| An admin with no grant removed from the roster | 5 minutes of roster cache (`ROSTER_CACHE_TTL`, per worker), plus 15 minutes |

There is no scheduled reconcile today. `docs/membership.md` records the timer
as not built. Until one runs, a missed push is unbounded. This spec asks the
deployment for an hourly `manage.py reconcile_membership`, which makes the
worst case 75 minutes. See Settings and open question 3.

### Revocation and sign-out

- **Revocation** deletes the member's refresh tokens. In
  `membership.apply_event`, the branch that already notifies Open WebUI and
  LiteLLM when a live membership ends (`corliss/membership.py:277-282`) also
  deletes every `OidcRefreshToken` for that DID. This is a tidy-up. The check
  at step 6 is what the rule depends on, and it holds whether or not this
  delete ran.
- **Signing out of Corliss** in a browser leaves refresh tokens alone. A
  browser session and an app on another device are not connected: signing out
  of the website must not stop Obsidian syncing on the phone. Open WebUI's
  back-channel logout on sign-out (`corliss/views.py:1807-1825`) is
  unchanged.
- **Removed from the registry while holding an access token**: the token
  works until `exp`. There is no revocation of issued access tokens.

## Discovery documents

One builder in `oidc.py`, served at two paths:

- `/.well-known/openid-configuration`, as today.
- `/.well-known/oauth-authorization-server`, new. MCP clients try this path
  first for an issuer with no path component, then the OpenID one.

Changes to the document:

| Field | Today | After |
|---|---|---|
| `grant_types_supported` | `authorization_code` | adds `refresh_token` |
| `token_endpoint_auth_methods_supported` | `client_secret_post`, `client_secret_basic` | adds `none` |
| `scopes_supported` | `openid`, `profile`, `email` | adds `offline_access` |
| `code_challenge_methods_supported` | absent | `["S256"]` |
| `client_id_metadata_document_supported` | absent | `true` |

Everything else is unchanged. MCP clients refuse to proceed when
`code_challenge_methods_supported` is absent. Claude uses CIMD only when both
`client_id_metadata_document_supported` and `none` are present, and otherwise
looks for a registration endpoint, which Corliss does not have.

Claude caches discovery for about five minutes, so a change here takes that
long to reach it.

## Data model and migrations

One migration, `0007`. All logic that touches these rows lives on the models.

**`OidcAuthCode`, changed.**

| Field | Change |
|---|---|
| `client_id` | `CharField(255)` to `CharField(2000)`. A `client_id` is now a URL. |
| `redirect_uri` | `URLField` (200) to `CharField(2000)`. Loopback and custom-scheme URIs are not URLs Django's validator accepts, and 200 is short. |
| `code_challenge` | new, `CharField(128)`, blank |
| `resource` | new, `CharField(2000)`, blank |

Blank defaults, so codes in flight at deploy time still redeem.

**`OidcRefreshToken`, new.**

| Field | |
|---|---|
| `token_hash` | `CharField(64)`, unique. SHA-256 hex. |
| `user` | FK, cascade |
| `client_id` | `CharField(2000)` |
| `resource` | `CharField(2000)` |
| `scope` | `CharField(255)`, blank |
| `family` | `UUIDField`, indexed |
| `created_at`, `expires_at` | |
| `used_at` | null until rotated |
| `parent` | FK to self, null. The token this one was issued from. |
| `superseded_at` | null unless replaced during the grace window. A superseded token is never accepted. |

**`OidcClientDocument`, new.** `client_id` (unique), `document` (JSON),
`fetched_at`, `expires_at`, `last_error` (blank).

**`OidcConsent`, new.** `user`, `client_id`, `resource`, `created_at`. Unique
on the three together.

Cleanup: issuing a code deletes expired codes, and issuing a refresh token
deletes expired and used refresh tokens older than a day. No scheduled job.

All three new models are read-only in the Django admin, with delete allowed
on `OidcRefreshToken` and `OidcConsent` so an operator can disconnect a
client.

## Settings, secrets and deployment

### Corliss settings

| Setting | Default | Notes |
|---|---|---|
| `OIDC_RESOURCES` | empty | Resource URLs tokens may be issued for, each with a label and a kind (`sync` or `mcp`). Empty refuses every public client. |
| `OIDC_CLIENT_METADATA_ALLOWLIST` | empty | Exact URLs or origins. Empty accepts only Corliss's own documents. |
| `SYNC_RELAY_URL` | exists | Internal relay address. Already used by `/systems/`. Reused for C7. |
| `SYNC_RELAY_SERVICE_TOKEN` | empty | Shared credential for the relay's `/internal/vaults`, used to list and to create. Empty shows "not configured" on the Obsidian page. |

Token lifetimes are constants in `oidc.py` beside `CODE_TTL_SECONDS` and
`ID_TOKEN_TTL_SECONDS`: access 900 seconds, refresh 30 days, and
`REFRESH_REUSE_GRACE_SECONDS = 60`.

`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URIS` and
`OIDC_BACKCHANNEL_LOGOUT_URI` keep their meaning.

Each new setting goes in the README's settings table and `.env.example` in
the same change, and each new route in the Endpoints table.

### zai-ops changes

- **Public resource URLs**, defined once in `group_vars` and read by both
  roles, so the audience Corliss issues and the audience the relay expects
  cannot drift: the sync URL and the MCP URL. Corliss renders them into
  `OIDC_RESOURCES`. The relay renders them into `SCN_SYNC_RELAY_SYNC_AUDIENCE`
  and `SCN_SYNC_RELAY_MCP_AUDIENCE`.
- **The relay service token**, a generate-once secret under
  `/root/.zai-secrets` using the same `password` lookup as
  `corliss_membership_push_token`. Rendered into Corliss's env file as
  `SYNC_RELAY_SERVICE_TOKEN` and the relay's as
  `SCN_SYNC_RELAY_SERVICE_TOKEN`. Not DR-critical: losing it costs a
  regenerate and a replay of both roles.
- **`corliss_oidc_client_metadata_allowlist`**, default
  `["https://claude.ai"]`.
- **Relay issuer settings**, in the relay's rollout: `OIDC_ISSUER` is
  Corliss's public URL. `OIDC_JWKS_URL` is Corliss's internal address, which
  is already in `corliss_allowed_hosts` for the registry's push.
- **Hourly reconcile timer** on the Corliss CT running
  `manage.py reconcile_membership`. See Membership freshness.
- **No new proxy route for Corliss.** Every new path is on the existing host.
  Nothing in front of Corliss may block `160.79.104.0/21`, where Claude's
  discovery and token requests come from.
- `corliss_version` bump, and `docs/roles/corliss.md` updated for the new
  variables and the secret.

## C7. Obsidian page

One page for members that explains the service and holds their vaults.

- Route `vaults/`, `@member_required`. GET shows the page. POST creates a
  vault. A nav entry for members, labelled **Obsidian**.
- `corliss/sync_relay.py`, a new module, because the relay is an external
  system. An underscore, since a hyphen cannot be imported. Two functions,
  both with `Authorization: Bearer <SYNC_RELAY_SERVICE_TOKEN>`, a 5 second
  timeout and no redirects:
  - list: `GET <SYNC_RELAY_URL>/internal/vaults?did=<did>`
  - create: `POST <SYNC_RELAY_URL>/internal/vaults` with `{did, name}`

  `health.py` keeps its own liveness probe.
- The DID is always `request.user.did`, for list and for create. No request
  parameter chooses whose vaults are listed or who owns a new one.
- Nothing is stored in Corliss.

What the page shows, top to bottom:

1. **What this is.** Notes kept on SCN, readable and editable from Obsidian
   and from Claude, for as long as you are a member. That SCN's operators
   can read them.
2. **Your vaults.** Name, created and last change for each, and a form to
   create one: a name and a button. A member can have any number.
3. **Connect Claude.** The public MCP URL, with the steps to add it as a
   connector.
4. **Connect Obsidian.** Create a new empty vault in Obsidian, install SCN
   Sync, paste the public sync URL, sign in, pick a vault. On iPhone, leave
   **Store in iCloud** off.

The two URLs come from `OIDC_RESOURCES`. Each entry gains a kind (`sync` or
`mcp`) beside its label so the page can tell them apart.

Creating a vault:

- A POST with CSRF protection. The name is trimmed and must be 1 to 100
  characters.
- The membership gate that guards the page guards the POST.
- On success, redirect to the page, which now lists the vault.
- A `409` from the relay shows "you already have a vault with that name"
  beside the form, with the name kept.
- Any other failure shows that the vault could not be created right now.
  Nothing is retried.

Page states, following `/systems/`:

| State | Page shows |
|---|---|
| URL or token not configured | The instructions, and that vaults are not set up on this deployment. No form. |
| Relay unreachable, or a non-200 answer | The instructions, and that the relay cannot be reached right now. No form. |
| Answered | The list and the form, or that the member has no vaults yet and the form |

No state raises, and nothing else on the site depends on this page.

## Test plan

Open WebUI sign-in is the standing regression. `corliss/tests/test_provider.py`,
`test_gate.py` and `test_backchannel.py` must pass without edits to their
flow assertions after every change in this spec. Existing tests that assert
UI wording are not reviewed or rewritten here.

New test modules: `test_public_clients.py` (C1, C3, C4, C6, consent),
`test_cimd.py` (C2), `test_refresh.py` (C5), `test_vaults.py` (C7).

| Acceptance check | Automated here | Verified on the cluster |
|---|---|---|
| 1. Claude web: add the MCP URL as a custom connector, sign in, a tool call succeeds | Discovery at both paths carries the CIMD and PKCE fields. Authorize with an allowlisted `client_id`, the `claude.ai` callback, S256 and the MCP resource, with no `openid`, reaches consent and issues a code. Exchange returns an access token whose claims match the token contract and which verifies against the JWKS. | Yes |
| 2. Claude iOS: the same connector works from the phone | Same as check 1. Nothing differs on Corliss's side. | Yes |
| 3. Claude Code completes OAuth through the loopback redirect | Loopback match ignores the port for `localhost` and `127.0.0.1`. The two hosts do not match each other. A different path does not match. Consent is shown every time and includes the redirect host. | Yes |
| 4. scn-obsidian sign-in returns to the plugin and the relay accepts the token | Corliss's own document is served and resolves without a fetch. Authorize redirects to `obsidian://scn-obsidian` with code and state. The token's `aud` is the sync resource. | Yes, laptop and iPhone |
| 5. A removed DID: the next refresh fails with `invalid_grant` | Revoke through `apply_event`, then refresh: `invalid_grant`, family gone. The same with the delete skipped, to show the membership check alone is enough. | Yes |
| 6. Open WebUI sign-in still works | The three existing modules, unchanged. Plus: Open WebUI still receives the ID token as its access token, still needs `openid`, gets no consent screen, and is refused when the secret is blank. | Yes |
| 7. The Obsidian page shows the member's vaults and only theirs, and creates one | The relay is called with the signed-in DID only, for list and for create. A `did` in the query string or the form is ignored. Create needs CSRF, refuses an empty or overlong name, shows the duplicate-name message on `409`, and shows a failure when the relay is down. Not configured, unreachable and empty each render. A non-member is refused on GET and on POST. | Yes |

Further unit coverage:

- PKCE: missing challenge, `plain`, wrong verifier, verifier out of length.
- Resource: missing, unknown, repeated, trailing slash, mismatch at `token`.
- Refresh: rotation returns a new token, a replay inside the window returns a
  new pair and supersedes the first, a superseded token kills the family, a
  replay after the window kills the family, a replay after its successor was
  used kills the family, a concurrent pair both succeed and one result is
  superseded, expiry, wrong client, resource mismatch, scope cannot widen.
- CIMD fetch: non-https, private and loopback addresses, a redirect, an
  oversized body, a slow server, `client_id` mismatch, a bad redirect scheme,
  a URL outside the allowlist that is never fetched, cache hit, stale served
  on failure, failure remembered.
- Sign-in round trip: an anonymous authorize with all five parameters resumes
  with all five intact. A request over 2048 characters is refused.
- Consent: Cancel returns `access_denied`. A forged ticket is refused. A
  member revoked between the screen and the POST gets no code.

## Sequencing

**The relay is blocked on Corliss**, in this order:

1. **C6 first.** The relay's verifier needs a real access token to be written
   against: the claims above, the `typ` header, and the JWKS. C6 cannot ship
   alone, since only a public client receives such a token, but it is the
   part to settle and build first. The token contract section is the
   interface.
2. **C1 to C5**, before any real client can reach the relay: client lookup,
   CIMD, PKCE, redirect matching, refresh.

**Corliss is blocked on the relay** for C7 only. It needs the relay's two
`/internal/vaults` endpoints and their shapes. C7 ships after the relay's
Phase B.

**C7 now gates first use.** A vault can only be created here, so no member
can use Claude or Obsidian with SCN until release B is deployed. Releases A
and B are both on the path to the first working connection.

Suggested releases:

| Release | Contains | Unblocks |
|---|---|---|
| A | C1 to C6, discovery, consent, migration `0007` | The relay's verifier, then acceptance checks 1 to 6 |
| B | C7 | Acceptance check 7, and every member's first vault |

## Open questions

1. **The hosted Claude `client_id` URL.** Not published. The allowlist
   default is the `https://claude.ai` origin. Read the exact URL from the
   first real authorize request and decide whether to pin it.
2. **Grace window length.** 60 seconds is proposed. Confirm against Obsidian
   on iOS on a poor connection.
3. **The reconcile timer.** Needed for the freshness bound and not built.
   Confirm it lands with this work, and the interval.
4. **`/internal/vaults` shapes.** The relay's spec names the fields (root
   document ID, name, created, last change) and not the JSON, for the list
   and for the create response. Pin both before C7.
5. **Custom-scheme redirect, desktop and iOS.** Whether the browser hands
   `obsidian://scn-obsidian` back to Obsidian is not verified in two cases:
   after the consent POST and redirect, and when consent is remembered and
   `authorize` redirects with no tap at all. Check both on macOS and iOS. If
   either fails, a custom-scheme redirect ends on a page with a link the
   member taps.
6. **Whether public clients should get an ID token at all.** Allowed here
   when `openid` is requested. No current client needs it.

## Rollout

1. Land release A, run the suite, bump the version with `bin/release`, push
   the tag.
2. In the deployment repo: the new variables, the secret, the allowlist, the
   timer and the version pin, in one change.
3. Update the README: Endpoints table, settings tables, `.env.example`, the
   "Wiring up a relying party" section, and a section on public clients.
   Update `docs/membership.md` where it says the timer is not built.
4. Release B after the relay's Phase B is deployed.
