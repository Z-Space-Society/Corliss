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

## Layout

Corliss is a **single Django app**. Three models, one URL table; the two
protocol halves are plain modules, not sub-apps. A future subsystem earns its
own app only by being genuinely standalone.

| Module | Responsibility |
| ------ | -------------- |
| `corliss/models.py` | `User` (DID-keyed), `AtprotoToken` (server-side PDS tokens + DPoP key), `OidcAuthCode`. |
| `corliss/atproto.py` | ATProto OAuth client: client metadata, DPoP, handle/DID resolution, PDS discovery, PAR, token exchange. |
| `corliss/oidc.py` | OIDC provider core: discovery document, auth-code issuance, `id_token` minting. |
| `corliss/views.py` | Every HTTP endpoint, both halves. |
| `corliss/urls.py` | Every route, flat and un-namespaced. |
| `corliss/signing.py` | Loads the signing keys, builds the JWKS. |

Two signing keys, one JWKS: **ES256 (P-256)** for atproto DPoP + client
assertion (atproto mandates it) and **RS256 (RSA)** for the OIDC `id_token`
(broad OIDC-client compatibility).

## Run locally

Requires [uv](https://docs.astral.sh/uv/) and a reachable Postgres.

```bash
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt

cp .env.example .env            # then edit DATABASE_URL etc.
createdb corlissdb              # or point DATABASE_URL at an existing DB
.venv/bin/python manage.py generate_keys   # dev signing keys, written to ./keys/

.venv/bin/python manage.py migrate
.venv/bin/python manage.py collectstatic --noinput   # whitenoise manifest storage needs this
.venv/bin/python manage.py runserver
```

Configuration is entirely env-driven — see [`.env.example`](.env.example) for
the full list. `.env` is git-ignored; **never commit secrets or private keys**.
`CHAT_URL` drives the nav's "Chat" link and can be left blank.

**Local-dev `client_id` caveat:** atproto requires `client_id` to be a public
HTTPS URL serving `client-metadata.json`, so a real end-to-end login from
`runserver` needs a tunnel (e.g. `cloudflared tunnel --url
http://127.0.0.1:8000`) with `PUBLIC_BASE_URL`, `CSRF_TRUSTED_ORIGINS`, and
`ALLOWED_HOSTS` pointed at it.

### Tests

```bash
.venv/bin/python manage.py collectstatic --noinput   # once; page tests render {% static %}
.venv/bin/python manage.py test
```

### Admin

```bash
manage.py make_admin alice.bsky.social   # promote an ATProto identity (keyed on DID)
manage.py ensure_admin                   # idempotent break-glass local admin;
                                         #   reads CORLISS_ADMIN_PASSWORD
```

## Endpoints

| Endpoint | Path |
| -------- | ---- |
| Landing (authenticated) | `/` |
| Login / logout | `/login`, `/logout` |
| ATProto callback | `/oauth/callback` |
| ATProto client metadata (**is** the `client_id`) | `/client-metadata.json` |
| OIDC discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| OIDC authorize / token | `/oidc/authorize`, `/oidc/token` |
| Django admin | `/admin/` |

Discovery and JWKS sit at the root deliberately: an OIDC issuer of
`https://example.com` must serve its discovery document at
`https://example.com/.well-known/openid-configuration`.

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
at a pinned ref, builds the venv, migrates, collects static, and renders the
env file.

Required in production: `SECRET_KEY`, `DATABASE_URL`, `ALLOWED_HOSTS`,
`PUBLIC_BASE_URL`, `CSRF_TRUSTED_ORIGINS`, the two key paths, and the
`OIDC_CLIENT_*` values.

> **History:** Corliss began as the `zai-auth` app inside
> [zai-ops](https://github.com/Z-Space-Society/zai-ops) and was extracted here;
> pre-extraction history lives in that repo.
