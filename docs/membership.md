# Membership — who is allowed in

Part of the [Corliss](../README.md) documentation. Signing in is not the same as
being let in; this is everything about the difference — where the answer lives,
how Corliss caches it, how the cache is rebuilt from nothing, and how access
ends.

| | |
| --- | --- |
| [Applications](#applications--asking-and-who-has-asked) | asking to join, and the admin's queue |
| [Deciding](#deciding--approve-tier-change-revoke) | approve, tier change, revoke |
| [Reconciliation](#reconciliation--rebuilding-the-cache-from-the-registry) | rebuilding the cache from the registry |
| [Signing in as an admin](#signing-in-as-an-admin) | why an admin's login differs from the first call onwards |
| [GATE](#gate--where-membership-is-actually-enforced) | where membership is actually enforced |
| [Back-channel logout](#back-channel-logout--ending-a-session-not-waiting-it-out) | ending a session rather than waiting it out |

---

Corliss authenticates people; it does not decide who may use the cluster. That
lives in an external registry (append-only grant and revocation records, held
in a HappyView space). Corliss keeps a **cache** of the registry's answer in
`MembershipCache`, and the registry is authoritative in every disagreement.

**The registry pushes; nothing on the request path ever pulls.** A membership
question raised by a login, a page render or an OIDC exchange is answered from
the cache and the roster — never by asking the registry inline. That is what
keeps a registry outage from becoming a login outage, and it is why a cache miss
is a no rather than a lookup. Corliss *can* read the registry as itself, through
a separate read-only door used only by
[Reconciliation](#reconciliation--rebuilding-the-cache-from-the-registry), which
is an operator action and a scheduled job. On each grant or revocation the
registry POSTs to `/membership/events`, authenticated by a shared bearer token
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

## Applications — asking, and who has asked

An application is a `membership.request` record with rkey `self` in the
**applicant's own PDS** — one per account, world-readable, carrying a timestamp
and an optional short note and nothing else. Both ends of it live here: a
signed-in non-member writes one from the home page, and `/manage/` lists them
above the member roll.

### Applying

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

### The queue

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

### Deciding — approve, tier change, revoke

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

## Reconciliation — rebuilding the cache from the registry

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

**Not built yet: the systemd timer and the run at boot** — wiring only, since
`manage.py reconcile_membership` already exits non-zero on an incomplete report,
which is what lets a scheduled run fail loudly instead of logging success over a
half-empty cache.

## Signing in as an admin

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

## GATE — where membership is actually enforced

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
the next click. They are `<span>`s rather
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

## Back-channel logout — ending a session, not waiting it out

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

Gating delivery on that row would make sign-out and revocation silent no-ops for
every session predating the feature — which, on deploy day, is all of them. It is
the same trap GATE avoids by enforcing at `/oidc/authorize` rather than at login,
and it takes the same answer: act on what is always true (the RP is registered,
and we know the member's `sub`) rather than on a record that only exists going
forward. The row supplies `sid` when we have one; the RP's own lookup by `sub`
does the work when we don't.

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

