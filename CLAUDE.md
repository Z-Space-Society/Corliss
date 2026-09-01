# CLAUDE.md — architecture invariants

Living document. These are constraints that should not drift. If a change
appears to require breaking one of these, stop and raise it rather than
working around it.

Scope is **this repo only**. Cluster-wide concerns (containers, roles, the
gateway's own config) belong to
[zai-ops](https://github.com/Z-Space-Society/zai-ops); the membership lexicons
and the Lua that serves them belong to
[member-registry](https://github.com/Z-Space-Society/member-registry). Corliss
consumes both and owns neither.

**What Corliss is:** the cluster's session broker. It runs the ATProto OAuth
client upstream and mints OIDC downstream — it *is* the bridge, not a client of
one. Members sign in with their handle; cluster apps are plain OIDC relying
parties.

## Documentation maintenance (IMPORTANT)

[`README.md`](README.md) is the reference manual for this app and is unusually
complete. **Keep it in sync in the same change that alters behavior** — never
leave docs for "later":

- **New/changed endpoint** → the Endpoints table.
- **New/changed setting** → the relevant settings table *and*
  [`.env.example`](.env.example). A setting that exists in one and not the other
  is the failure mode this rule exists to prevent.
- **A property that has a plausible wrong answer** → state it as a bullet with
  the reason, matching the surrounding style. The README's value is that it
  records *why* each non-obvious choice is that way; a change that removes a
  reason without replacing it makes the file worse than a shorter one.
- **A defect production found** → write down what would have caught it, not
  just the fix.

## Identity and keys

- **DID is the primary key, everywhere, forever.** `User` is DID-keyed;
  `MembershipCache` is keyed by DID with no foreign key to `User`. Handles,
  names and emails are mutable, optional, and display-only — never key, compare,
  or store against them.
- **The PDS seeds the name and the email; the member owns them.** `username` and
  `pds_url` are the PDS's facts and are overwritten at every login.
  `display_name` and `email` are *offered* at login and written only when the
  stored value is blank, because `/account/` lets the member change them — an
  edit that reverts at the next sign-in would make that page a lie. A non-blank
  value **is** the "edited locally" flag; do not add a column for it, and do not
  restore the unconditional overwrite. `display_name` is one free-form string,
  matching atproto's `displayName`: `first_name`/`last_name` come free with
  `AbstractUser` and are used nowhere, and splitting a name across them would be
  a guess this app does not have to make.
- **The OIDC `sub` IS the DID.** No opaque internal id, no mapping table at the
  boundary. A relying party keying on `sub` is keying on the DID, and that is
  the contract.
- **Two signing keys, one JWKS, and they do not collapse into one.** ES256
  (P-256) for atproto DPoP and the `private_key_jwt` client assertion — atproto
  mandates it — and RS256 for the OIDC `id_token`, for broad relying-party
  compatibility. RSA cannot produce ES256, which is the whole reason there are
  two.
- **The atproto `client_id` IS a URL** — `<PUBLIC_BASE_URL>/auth/client-metadata.json`.
  Change the origin *or* that path and you have minted a brand-new client
  identity: every member re-consents at their PDS and in-flight sessions die.
  Nothing errors; it silently becomes a different client. Bundle any such move
  into a single cutover rather than paying the re-consent twice.
- **Private keys never leave `keys/`, and only public halves are served.**
  Git-ignored, mode `0600`, provisioned out-of-band in production.

## Membership is a cache, never truth

- **The registry is authoritative in every disagreement.** `MembershipCache`
  holds a cache of a *computation* — latest-event-wins over an append-only log
  of grants and revocations — not a second copy of a fact.
- **Corliss must always be able to rebuild it from the registry alone.**
  `reconcile` is what makes an empty database recoverable and is therefore a
  precondition for gating anything on the cache. Any change that makes the cache
  unrebuildable breaks the recovery path, whatever else it fixes.
- **Never write back to the registry as though the cache were a source.**
- **Order events by the rkey's TID, never by `grantedAt`/`revokedAt`.** Those are
  second-resolution, so they cannot separate two events in one second and cannot
  stop a retried stale grant from resurrecting a revoked member.
- **A grant can exist for someone who has never logged in.** That is how an
  invitation works, and it is why the cache has no FK to `User`.
- **`MembershipCache` is read-only in the Django admin** — no add, no change, no
  delete, not even for a superuser. An edit there is either reverted by the next
  push or, until then, a membership no record backs.
- **Nothing on the request path ever pulls from the registry.** A membership
  question raised by a login, a page render or an OIDC exchange is answered from
  the cache and the roster; a cache miss is a **no**, never a lookup.
  Reconciliation is an operator action and a scheduled job, never a step in
  somebody's login.

  Corliss *can* read the registry as itself — `syncMembers` exists and
  `fetch_events` calls it — so the constraint is architectural, not a
  capability we lack. **Do not add a cache-miss fallback that asks the
  registry.** It would put HappyView in the login path, turning a registry
  outage into a login outage, and would take the recovery path down with it
  since `/manage/` and the reconcile button are reached by logging in.
  member-registry's own invariant says the same thing from the other side: "Do
  not introduce a HappyView dependency into the request path."

## The two registry doors, which must not merge

Corliss reaches the registry two ways, deliberately with different credentials
so widening one cannot widen the other.

- **Reads: `MEMBERSHIP_REGISTRY_TOKEN`, a shared token, `syncMembers`, read-only.**
  It must **never** gain write scope. It is an XRPC *query*, so the token travels
  in the URL — which is survivable only because the call goes to the registry's
  **internal** address, out of any edge or CDN log.
- **Writes: the acting admin's own session, with a DPoP proof.** There is
  deliberately no Corliss credential that can author a grant. The registry gates
  procedures behind DPoP, which a service holding only a shared token cannot
  produce — that asymmetry is load-bearing, not an accident to route around.
- **The DPoP proof names the public origin, not the address dialled.** The
  registry routes by virtual host and rebuilds the request URI from the `Host`
  header. Signing the internal address earns `401 DPoP proof htu mismatch`;
  presenting a bare IP earns `HTTP 421 Unknown host`. `MEMBERSHIP_REGISTRY_HOST`
  exists for exactly this, and `corliss/tests/test_approve.py` fails if the proof
  stops naming the public host. Do not "simplify" that test away.
- **An integration that is not configured says so; it never 500s and never
  fails open.** A blank registry or LiteLLM setting disables the surface with a
  visible reason.

## Reaching other services

- **Server-side Python cannot fetch our own public origin.** Cloudflare's
  Browser Integrity Check refuses non-browser user agents with `error code:
  1010`. **The split is by HTTP library, not by endpoint** — `requests` and
  `httpx` get 200, bare `urllib` gets 403 — and it is invisible from a shell
  where `curl` passes. This shipped back-channel logout fully built and
  completely inert.
- **So every service-to-service call takes the internal address.**
  `LITELLM_URL` is not `API_URL`; the registry URL is internal; the relying
  party's back-channel endpoint is internal. Conflating a public origin with an
  internal one breaks things *quietly*, which is why it is an invariant rather
  than a preference.
- **The one leg that cannot be made internal is the return.** A relying party
  validates our `logout_token` by fetching our discovery document and JWKS at
  the *public* origin, because `iss` must match. Delivery therefore still depends
  on the edge, and the RP's short token lifetime is the bound that holds when it
  fails.

## GATE and ENTITLE are two questions

- **`may_enter(did)` passes on an active grant *or* a current place on the admin
  roster.** The second clause is what makes closing the gate survivable: a
  Corliss rebuilt from nothing has an empty cache and would otherwise lock out
  every admin, including the one who would press the button that refills it. The
  roster is a public record needing no database. Never gate on the cache alone.
- **The roster clause buys that admin nothing else.** Entitlements come from
  `membership_for`, so a roster admin with no grant enters and receives nothing
  they were never granted.
- **`require_membership` is a per-view helper, never middleware.** Middleware
  covers everything by default and these would have to be remembered as
  exemptions: `/admin/login/` (the break-glass account is not on the roster and
  will never have a cache row), `/manage/` (gated on the roster, no database, and
  it holds the reconcile button), and `/` (where every refusal lands).
- **Gate at `/oidc/authorize`, not at login.** Only the exchange is reached every
  time, so only it can refuse a session established before the gate existed or
  one whose owner has since been revoked.

## One admin, and the roster is what says so

Corliss used to hold these apart — a roster admin and a Django staff member were
different people by design. They are now one thing, deliberately merged: "who is
an admin" having two answers was a confusion that cost more than the separation
bought, and `is_staff` was referenced *nowhere* in this app's own logic. It only
ever opened Django's `/admin/`.

- **`is_cluster_admin` is the authority**, and it is a live read of the atproto
  roster record. It governs `/manage/` and `/systems/`, and it is never stored.
- **`is_staff` is a mirror of it, never a second source.** `membership.appoint_admin`
  writes both halves; `views._heal_staff_flag` re-derives it at every login, so a
  half-failed write self-corrects rather than drifting. `User.is_cluster_admin`
  still never consults `is_staff` — the mirror must not become the authority.
- **`is_superuser` stays a separate, explicit opt-in.** `is_staff` alone opens the
  admin index with no model permissions, which is why merging it was affordable;
  `--superuser` bypasses every permission check and has to be asked for by name.
  `_heal_staff_flag` skips superusers in both directions, so it can never lock out
  an account somebody deliberately escalated.
- **Authority is asked at the event's timestamp** (`Roster.was_admin_at`), never
  "is this DID an admin now". Removing an admin ends their authority going
  forward; it must not un-write what they already approved.
- **Two refusals guard the roster**, both in `membership.dismiss_admin`: never
  leave zero current admins (an existing-but-empty roster fails closed everywhere,
  and the registry's `BOOTSTRAP_ADMIN_DID` escape only covers an *absent* record),
  and never remove `SCN_SERVICE_DID` (it performs the writes; off the roster it
  fails GATE and cannot sign back in to be restored).

## Editing the roster needs the service account, and that is not a shortcut

The roster is a record in the service account's own repo, and an atproto repo is
writable only by its owner — so the acting admin cannot write it, and Corliss
brokers: it verifies the actor is a current admin, then spends the service
account's stored session. The actor's DID is recorded in the entry (`addedBy` /
`removedBy`).

- **This is not a Corliss credential that can author grants**, and the two must
  not be conflated. The service session writes the *roster*; grants are still
  authored only by the acting admin's own session. See the rejected list.
- **Appointing is two writes, and the second needs the registry.** Space write
  access is what actually lets a new admin approve anyone — `space:put_record`
  requires it — and only the space authority can grant it. The roster write goes
  first, so a failure leaves nothing changed rather than a half-admin; a failed
  space sync is *reported, never raised*, because the roster write already
  happened and both halves are idempotent.
- **An inert credential cannot do this and it was not for lack of trying.**
  HappyView's XRPC routes reject Bearer auth outright (probed against the
  cluster), the admin API has no space-member routes, and space credentials
  cannot manage membership. `/oauth/sessions` verifies the tokens it is handed by
  calling the PDS with a DPoP proof signed by the key it provisioned, so an
  app-password token cannot register a session at all. The atproto handshake is
  the only way, and that is settled — do not re-propose a password field.
- **Authenticating it must never call `auth_login`.** `views.manage_unlock` starts
  the handshake and `callback`'s `service_link` branch stores the tokens and
  redirects; the absence of `auth_login` there is the entire mechanism, and it is
  what keeps an admin signed in as themselves through the round trip. The first
  cut did call it and swapped the admin's session for the service account's.
- **The word is "Authenticate", never "sign in".** The reader is already signed
  in and stays that way; the wrong word makes an errand read as a logout.
- **A lapse degrades only appointment.** Approve, revoke, login and everything
  members touch run on the admins' own sessions. Keep it that way.
  `membership.refresh_service_session` keeps it alive on the reconcile run and
  the lock on `/manage/` shows its health, so a lapse is found before it is
  needed.

## The console is one member table

- **Admins are members**, enforced in `membership.appoint_admin`. So there is no
  separate admins table: admin is a column, and `Make Admin` / `Revoke Admin` are
  in the member's own panel. The service account holds no grant and therefore
  never appears — it is infrastructure, not a person.
- **The table carries no controls.** Every write a member can be the subject of —
  tier, revocation, admin — lives in a panel opened by clicking their handle. A
  `Change` column sets the table's width from its widest control rather than from
  anything anybody reads, and that is what made this table scroll sideways. The
  panel opens on `:target` and closes with an ordinary link, **with no script**:
  this page holds the reconcile button and is how a broken deployment gets fixed,
  so its controls must not depend on JS loading.
- **Only active memberships are listed.** A revoked person is history and the
  registry is where history lives; re-inviting the same handle readmits them,
  which is what readmission always was.
- **Declining an application is a revocation, and needs nothing new at the
  registry.** Membership is latest-event-wins over grants and revocations, so a
  revocation with no grant before it *is* "not a member". It survives reconcile
  because it is an admin-authored event, which is what keeps the applicant out
  of the queue after a rebuild. It stamps a reason so the log does not read as
  the revocation of a membership that never existed, and it **refuses when the
  subject is a current member** — the queue can hold one ("asked again"), and
  there Decline would silently revoke a sitting member and dismiss them as an
  admin. Revoking a member is a decision taken on their own row.
- **A DID is never text.** Handles are what a reader sees, with the DID on the
  cell's `title`. `membership.ensure_user` records the handle when a grant is
  written, so a member is named rather than numbered from the moment they are
  admitted rather than from their first sign-in. The one exception is a member's
  own panel, which is about exactly one person: there the DID is selectable text,
  because a `title` cannot be copied and there is no column of them to keep
  narrow. **Tables stay handles-only** — that is what the rule is protecting.
- **A name is a second line under the handle, never a column.** It is annotated
  off the `User` row in the same subquery pass as `is_admin` — never through
  `membership.handles_for`, whose fallback is a DID-document fetch per unknown
  DID. This page has to render when the network does not.
- **Admin status renders from `is_staff`**, the local mirror, not a roster read
  per request. The roster stays the authority; `_heal_staff_flag` re-derives the
  mirror at every login and `appoint_admin` writes both together.
- **Revoking a member who is an admin cascades, admin first.** That order is the
  one whose half-done state is safe: a member who is not an admin, rather than a
  non-member still holding registry write access.

## Development bypasses

- **`/auth/dev-login` is a complete authentication bypass** and is guarded three
  ways: off by default, registered only when `DEBUG` and `DEV_LOGIN_ENABLED` are
  both true with the view re-checking, and a Django system check
  ([`corliss/apps.py`](corliss/apps.py)) that **errors** if the flag is set
  without `DEBUG`, so a production env file carrying it fails the deploy rather
  than quietly serving an open door. `DEV_ADMIN_DIDS` carries the same three
  guards. **Never weaken any of them**, and never add a fourth bypass without
  the same treatment.
- Dev members are keyed `did:dev:<handle>` — not a registered DID method, so
  they can never collide with a real DID.
- **atproto login genuinely cannot work over localhost**, and the protocol's
  own localhost exception is deliberately not used (see the README for why).
  Nothing is misconfigured when a loopback login fails; do not "fix" it.

## API keys and LiteLLM

- **Nothing about a key is stored here.** LiteLLM is the source of truth; the
  plaintext exists for exactly one render. A stored key would be a credential in
  a second place for no gain.
- **The provisioner key is a `proxy_admin` virtual key, never the master key**,
  so a compromised Corliss costs one revocation rather than a proxy-wide
  rotation.
- **No request ever chooses whose keys it acts on.** The provisioner can act for
  anyone, so every operation re-establishes the asking DID server-side: issuance
  proves an active grant, revocation proves ownership, and the key list is
  filtered by `user_id` twice — once as a query parameter and once over the
  response. Handing one member another's keys would be this module's worst
  failure; the second filter costs one comparison.
- **The LiteLLM `user_id` IS the member's DID.** Not a handle, not a hash — that
  is what makes provisioning idempotent on retry.
- **A tierless membership is refused a key, and that is a security check.** A key
  with no team inherits every model, so an unscoped key is *more* permissive than
  any tier.
- **Tier slugs are the registry's vocabulary, resolved to LiteLLM teams by
  `team_alias` at runtime.** Never hold a team id — it is generated at creation
  and would have to be carried out of Ansible by hand.

## Layout

- **A single Django app, flat.** The protocol halves are plain modules, not
  sub-apps. A future subsystem earns its own app only by being genuinely
  standalone.
- **One relationship, one module.** `membership.py` owns the whole registry
  relationship; `litellm.py` is the only place a gateway credential is used;
  `oidc.py` owns the provider surface including its outbound logout POST. A
  second module talking to the same external system is the thing to avoid.
- **`views.py` is every endpoint and `urls.py` every route, un-namespaced.**

## Releases and deploy

- **`version` in `pyproject.toml` and the `vX.Y.Z` tag are one fact**, and
  [`bin/release`](bin/release) is what keeps them that way. The bump is not
  cosmetic: `uv.lock` records the project version and the deploy runs
  `uv sync --locked`, so bumping without re-locking fails the deploy outright.
- **Dependencies are pinned exactly (`==`) with the full tree locked.** Upgrades
  are a deliberate, reviewable edit, never a silent resolve at install time.
- **Push the tag, not just the commits.** `git push` does not push tags, and a
  local-only tag fails the zai-ops role at checkout with `pathspec 'vX.Y.Z' did
  not match any file(s) known to git` — which reads like a bad pin.
  `git ls-remote --tags origin` is the check that tells the two apart.
- The footer's build stamp reports the deployed version, which is the quickest
  confirmation a deploy actually landed.

## Conventions

- **Probe each leg as it is built, not the whole chain at the end.** Three of the
  four defects production found in the registry integration were dependencies
  written down in the docs and never once probed. A documented dependency is not
  a verified one.
- **Run the suite before claiming done** (`./manage.py test`; `collectstatic`
  once first, since page tests render `{% static %}`).
- **Match the surrounding style** — comments and docs explain *why*, not *what*.

## Rejected — do not re-propose

- **Gating access on `MembershipCache` alone.** It makes the recovery path depend
  on the very thing being recovered.
- **Gating back-channel logout delivery on an `OidcSession` row.** This was a bug
  in the first cut of v0.6.0: rows only start existing when the feature ships, so
  gating on one made sign-out and revocation silent no-ops for every session that
  already existed — which, on deploy day, is all of them. Act on what is always
  true (the RP is registered, we know the `sub`), not on a record that only
  exists going forward.
- **Storing issued API keys.** They cannot be re-shown, and LiteLLM already knows
  every fact about them worth reading.
- **A permission system.** There are no objects to protect and no verbs to grant;
  a tier is a pointer to a LiteLLM team and the rest is two booleans. Tiers are
  enforced by LiteLLM, model gating by Open WebUI's own groups. See the project
  vault's ADR-003.
- **A Corliss credential that can author grants.** It would break
  admin-authored-only, which is what author-based verification at the registry
  exists to record. Still rejected. The service-account session Corliss holds
  writes the **roster** and calls `setSpaceAccess`; it must never grow a path
  that writes a grant or a revocation — those stay authored by the admin who
  decided, on their own session.
- **atproto's `http://localhost` development client.** Lowest fidelity exactly
  where this app is most likely to break — see the README.
