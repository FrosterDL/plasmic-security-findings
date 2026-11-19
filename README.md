# Plasmic — security findings

Findings in **Plasmic** (GitHub: [plasmicapp/plasmic](https://github.com/plasmicapp/plasmic),
"Visual builder for React"), at commit
`7d66db54ef6090b504b5ff4d920328b6701237e9` (2026-11-16). No tagged releases;
versioning is per npm package (@plasmicapp/loader-nextjs 2.0.31,
@plasmicpkgs/plasmic-cms 0.0.335, among others).

Each finding was reproduced against a local deployment of the real code
(PostgreSQL 16 + the real WAB platform backend, seeded per the project's own
dev setup). Full methodology, controls and results: [EVIDENCE.md](EVIDENCE.md).

Finder: FrosterDL

## Findings

1. **PL-001 — Stored XSS: Plasmic CMS rich-text content is stored unsanitised
   and rendered as raw HTML** (Moderate–High, provisional)
   [PL-001-advisory.md](PL-001-advisory.md) · CWE-79 ·
   harnesses: [harness_cms.py](harness_cms.py),
   [harness_browser.cjs](harness_browser.cjs)

2. **PL-002 — Email-verification bypass: verification tokens are returned to
   anonymous callers** (Moderate–High, provisional)
   [PL-002-advisory.md](PL-002-advisory.md) · CWE-862/200/863 ·
   harness: [harness_p01_email_verification.py](harness_p01_email_verification.py) (7/7)

3. **PL-003 — Unauthenticated file upload to public asset storage
   (script-bearing SVG and arbitrary HTML)** (Moderate–High, provisional)
   [PL-003-advisory.md](PL-003-advisory.md) · CWE-862/434/79 ·
   harness: [harness_p02_uploads.py](harness_p02_uploads.py) (4/4)

4. **PL-004 — Default "fake" data-source operation key lets unauthenticated
   attackers forge operation IDs and run arbitrary SQL with stored
   credentials** (High, provisional, conditional on the default configuration)
   [PL-004-advisory.md](PL-004-advisory.md) · CWE-798/321/862/89 ·
   harness: [harness_p04_pg.py](harness_p04_pg.py) (6/6),
   [forge_opid.mjs](forge_opid.mjs)

5. **PL-005 — Unpublished (preview) project bundles are served to anyone
   holding the public project token** (Moderate, provisional — with an
   explicit vendor-intent caveat in the advisory)
   [PL-005-advisory.md](PL-005-advisory.md) · CWE-863/200

The upstream repository has private vulnerability reporting disabled and no
SECURITY.md; the vendor's documented security contact is
security@plasmic.app (Plasmic docs, Security page). The vendor has not been
contacted yet. These findings are disclosed here and are being submitted to
VulDB with CVE requests; no CVE has been assigned and no other CNA has been
approached.
