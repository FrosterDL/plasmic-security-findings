# Plasmic — Live Reproduction Evidence

Date: 2026-11-17 (Asia/Riyadh). Target: plasmicapp/plasmic @ **7d66db54ef6090b504b5ff4d920328b6701237e9** (master, 2026-11-16).
Duplicate baseline: CLEAN (NVD 0, OSV 0, GitHub Advisory DB 0, VulDB none) + one prior
vendor-acknowledged forum-disclosed SQLi (2026-06, different root cause) — see ../BASELINE.md.
GitHub-submittability: **PVR DISABLED** (`GET /repos/plasmicapp/plasmic/private-vulnerability-reporting`
→ `{"enabled": false}`), no SECURITY.md ("No security policy detected" on /security/policy).
Vendor disclosure channel per Plasmic docs: security@plasmic.app. Packets HELD privately.

## Deployment (native, no Docker — maximum local subset = the full platform)
- Postgres 16 native; roles/db created exactly per `platform/wab/tools/docker-dev/db-setup.bash`
  (wab/superwab, db `wab`, uuid-ossp). Prod uses PG18; mismatch is warn-only in their script.
- `pnpm install` in `platform/` (pnpm 11.10.0). Two sandbox workarounds were needed and are
  environment-only, not product changes: node headers staged locally for node-gyp
  (`npm_config_nodedir`), and the clone's group ownership normalised to root:root because
  gid 65534 is outside this VM's namespace mapping and pnpm's lockfile chown failed with EPERM.
- TypeORM migrations: all executed successfully. `make` in platform/wab generated model
  classes/parsers. `pnpm seed` created: admin@admin.example.com (admin),
  user@example.com (user1, id 596b2388-a382-4d9f-a9fd-e1c2552d5a07),
  user2@example.com (id 360f3130-a981-4117-ba4d-5ff4573af0d3) — password is the public
  DEFAULT_DEV_PASSWORD constant in DbMgr.ts (dev-only seed).
- Backend: `tools/backend-server.bash` (app server on :3004) with MAX_HEAP_SIZE=3072,
  NODE_ENV=development. Login verified for all three users (POST /api/v1/auth/login → status:true).
- Second backend run added S3_ENDPOINT=http://127.0.0.1:4569 + test AWS creds, backed by a
  local S3 mock (live-repro/s3mock.py — storage-layer test double only; all WAB code is real).
- No ~/.plasmic/secrets.json exists on this host (relevant to PL-004 precondition).

## PL-001 — Stored XSS via Plasmic CMS rich text (CONFIRMED end-to-end)
- Harness A (server half) `harness_cms.py` — **8/8 PASS**: as user1, created CMS database +
  table (text + rich-text fields) via CMSE API; attack row's rich-text body =
  `<img onerror>` + `<svg onload>` payloads, control row = benign HTML. Payload returned
  **byte-for-byte** by the API and stored verbatim in Postgres `cms_row.data`
  (DbMgr.createCmsRows has `// TODO: Verify that data is valid per field type!!` — no
  validation/sanitisation). Cross-user controls: user2 → 403 on read and write of user1's CMS.
- Harness B (renderer, jsdom) `render/harness_render.cjs`: real published
  @plasmicpkgs/plasmic-cms@0.0.335 tree (CmsCredentialsProvider → CmsQueryRepeater →
  CmsRowField) fetching live from the local public CMS API placed the payload in the DOM
  verbatim with live onerror/onload attributes (jsdom does not fire those events — noted).
- Harness C (renderer, real Chromium) `render/harness_browser.cjs` — **5/5 PASS**:
  same component tree bundled (esbuild) and opened in headless Chromium (Playwright):
  `window.__xss = ["img-onerror", "iframe-srcdoc"]` — payload scripts EXECUTED in the page.
  (The `<svg onload>` vector did not fire in this Chromium run; img-onerror and
  iframe-srcdoc did. Sink: plasmicpkgs/plasmic-cms/src/components.tsx renderValue(),
  RICH_TEXT → dangerouslySetInnerHTML, no sanitiser anywhere in the package.)

## PL-002 — Email-verification token returned to anonymous callers (CONFIRMED)
- Harness `harness_p01_email_verification.py` — **7/7 PASS**:
  1. Signed up `victim-not-owned@example-corp.com` (mailbox not controlled) → account
     created, Postgres `waitingEmailVerification = t`.
  2. Control: token minted for a non-existent email (decoy) → confirmEmail
     `{status:false, reason:"InvalidToken"}`; wrong token → same rejection; flag stays `t`.
  3. Attack: `GET /api/v1/auth/getEmailVerificationToken` with **no session at all**
     returned a REAL token for the victim email; `POST /api/v1/auth/confirmEmail` from the
     attacker's own session → `{status:true}`; Postgres flag flipped to `f`;
     GET /api/v1/auth/self → 200 as the victim email. Account fully verified under an
     email the attacker does not own. Endpoint has no auth and no rate limiter
     (AppServer.ts registration; handler auth/routes.ts getEmailVerificationToken never
     checks the caller; DbMgr.createEmailVerificationForUser calls allowAnyone()).

## PL-003 — Unauthenticated upload to public asset storage (CONFIRMED)
- Harness `harness_p02_uploads.py` — **4/4 PASS** (backend run with S3 configured):
  - `POST /api/v1/image/upload` with NO Plasmic session (only the public anonymous CSRF
    token any visitor can fetch): script-bearing SVG → 200
    `{"dataUri":"https://site-assets.plasmic.app/e3b53701f67f2480a24773c0778d6156.svg","mimeType":"image/svg+xml"}`;
    object stored verbatim, served `image/svg+xml` (SVG is passed through unsanitised by
    design in routes/image.ts downscaleImage; uploadFileToS3 uses ACL public-read).
  - `POST /api/v1/cmse/file-upload` with NO session and NO CSRF token at all: HTML file
    with attacker-controlled `text/html` mimetype → 200 with public URL; object stored
    verbatim, served `text/html`. Handler routes/cmse.ts cmsFileUpload never calls
    userDbMgr/getUser (every sibling handler does).
  - Pre-S3 runs failed only with `CredentialsProviderError` (AWS layer) — i.e. requests
    passed all Plasmic-side checks unauthenticated and reached the storage call.

## PL-004 — Default "fake" data-source operation key → forged opId → unauthenticated arbitrary SQL (CONFIRMED)
- Harness `harness_p04_pg.py` — **6/6 PASS** (plus earlier HTTP-variant run):
  - Precondition verified: no ~/.plasmic/secrets.json → getOpEncryptionKey() == "fake"
    (server/secrets.ts:74-76; loadSecrets returns {} on missing file; the file header says
    "Plasmic should run without any secrets.json file").
  - Setup (owner user1): Postgres data source → local wab DB (stored credentials),
    project allowed.
  - Control A: owner-issued opId (UUID) executed unauthenticated via
    POST /api/v1/server-data/sources/:id/execute → 200 with data (the intended public
    data plane — shown for contrast).
  - Control B: opId forged with a WRONG key → 400 `Invalid opId`.
  - Attack 1 (read): opId forged OFFLINE with key "fake" (repo's own stable-encryptor
    algorithm, util/crypt.ts: pbkdf2/100k/sha512 + AES-256-GCM + hard-coded IV/salt),
    template = customRead `select count(*)::int as user_count from "user"` → **200,
    returned user_count=4** — arbitrary SQL read, no session, no cookies.
  - Attack 2 (write): forged customWrite `create table pwned_by_forged_opid (...)` → 200;
    marker table verified present via direct psql; dropped in cleanup.
  - The same "fake" fallback also keys getEncryptionKey() (app end-user JWT signing and
    OAuth authorization-code encryption, routes/app-oauth.ts) — recorded as related
    impact, not separately executed in this hunt.
  - Earlier HTTP-source run: forged opId also decrypted (error moved past opId validation
    to the fetcher), but execution stopped at the SSRF filter because this sandbox's DNS
    resolves public names to 198.18.0.0/15 (reserved) — environment artifact, correctly
    blocked by fetchUntrusted; the Postgres path proves execution without that artifact.

## PL-005 — Loader preview (unpublished) bundles with only the public project token (CONFIRMED, vendor-intent caveat)
- `GET /api/v1/loader/code/preview?projectId=<user1 project>&loaderVersion=10` with header
  `x-plasmic-api-project-tokens: <id>:<PUBLIC token>` → **200, 108,706-byte bundle** of the
  latest UNPUBLISHED revision of a project that has never been published.
- Controls: same project via `/loader/code/published` → 400 "has not been published yet";
  wrong token → 401; user1's token against admin's project → 401.
- Caveat (stated in the packet): DbMgr documents "Public tokens grant read access" and
  preview requires only checkProjectPerms "viewer", so the vendor may consider this
  intended. The counterpoint: published-vs-preview is the product's own distinction, the
  public token is embedded in live sites' client configuration, and draft/branch content
  (unreleased pages, hidden variants) is exposed to anyone holding it. Severity held at
  Moderate provisional pending vendor triage.

## PL-006 (minor, confirmed — no packet) — Unauthenticated loader prefill
- `POST /api/v1/loader/code/prefill/<real pkgVersionId>` with no auth → 200 `{}`;
  bogus ID → 404. Anyone can force repeated codegen + CDN prefill work for arbitrary
  package versions (cost/DoS amplification). Code comment in AppServer.ts: "intentionally
  no apiAuth()". `GET /api/v1/loader/chunks` also lacks apiAuth but returned 500 locally
  (loader-assets bucket not configured in this deployment) — not pursued.

## Negative results (tested, held — do not file)
- Project authorization is solid: cross-user GET project → 403 with explicit access-level
  message; anonymous → 401; project list returns only own projects; CMS cross-user 403.
- Loader published/versioned auth: wrong token 401, cross-project token 401.
- HTTP/GraphQL data-source fetchers use fetchUntrusted (request-filtering-agent):
  private/reserved IPs and external→internal redirects blocked (specs + live behaviour).
- Postgres fetcher CRUD parameterises values; request-time filter[] without a template is
  rejected (this is the June-2026 fix). No end-user SQLi found in CRUD paths.
- PlasmicCanvasHost (packages/host): hardened — exact studio origin allow-list, no
  postMessage listener; classic any-site→host attack does not work at this commit.
- Prototype pollution: not found ($state deep-set fork explicitly guards
  __proto__/constructor/prototype).
- SSRF via loader apiHost/host params: developer-config only, tokens cannot be
  redirected off-host (redirects re-anchored). Not a finding.

## Parked leads
- P-002/P-003 (packages audit): CLI export/sync path traversal via server-bundle file
  names (packages/cli export.ts / file-utils.ts) and shell injection via usedNpmPackages
  (npm-utils.ts execSync) — code-level confidence medium; NOT live-executed (needs a
  malicious/compromised project + a developer running sync/export). Parked per
  no-repro-no-file rule.
- P-004 (packages audit): javascript: hrefs pass through PlasmicLink unsanitised
  (react-web PlasmicLink.tsx) — cross-boundary only when href is data-bound to
  CMS/visitor input; not live-executed. Parked.
- P-008 (server audit): white-label openJwt protocol-relative open redirect
  (//evil.example passes startsWith("/")) — needs a valid team-issued JWT; code-confirmed,
  low impact, not live-executed. Parked.
- P-007 (server audit): studio data-source execute/op-id with omitted projectId
  (TypeORM undefined-criteria hypothesis) — untested hypothesis. Parked.
- Rich-text XSS family sinks in sibling packages (plasmic-wordpress, plasmic-graphcms,
  plasmic-contentful, plasmic-content-stack, commerce descriptionHtml) — same
  dangerouslySetInnerHTML pattern, code-confirmed, not individually live-tested;
  mentioned inside PL-001's packet as related, not filed separately.
