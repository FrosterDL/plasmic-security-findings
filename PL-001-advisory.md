# Advisory paste — PL-001 (GHSA-shaped; HELD PRIVATELY — plasmicapp/plasmic has private vulnerability reporting disabled and no SECURITY.md; do not submit on GitHub)

Title: Stored cross-site scripting via unsanitised Plasmic CMS rich-text content rendered with dangerouslySetInnerHTML

Ecosystem / package: npm / @plasmicpkgs/plasmic-cms
Affected versions: <= 0.0.335
Patched versions: None
Severity: Moderate–High (provisional)
Weakness: CWE-79

## Summary
Plasmic CMS rich-text fields accept arbitrary HTML through the CMS API. The
server stores the value byte-for-byte without validation or sanitisation
(DbMgr.createCmsRows performs no per-field-type validation), and
@plasmicpkgs/plasmic-cms renders rich-text values with
dangerouslySetInnerHTML and no sanitiser. A CMS content author can store script
payloads that execute in the browsers of all visitors of sites rendering that
content.

## Details
Server side (plasmicapp/plasmic @ 7d66db54ef6090b504b5ff4d920328b6701237e9):
platform/wab/src/wab/server/db/DbMgr.ts createCmsRows() — row data is stored
after field-name filtering only; the function carries a
"TODO: Verify that data is valid per field type!!" comment.
Renderer side: plasmicpkgs/plasmic-cms/src/components.tsx renderValue() returns
<div dangerouslySetInnerHTML={{ __html: value }}> for RICH_TEXT fields. No
DOMPurify or equivalent is used in the package.

## Proof of concept
On a local deployment of the repository (Postgres + WAB server):
1. As a CMS content author, create a CMS database and a table with a rich-text
   field via the CMSE API.
2. Create a row whose rich-text value is:
   <p>hello</p><img src=x onerror="window.__xss=(window.__xss||[]).concat('img-onerror')">
   plus an iframe-srcdoc variant. A control row holds benign HTML.
3. The payload is returned byte-for-byte by the CMS API and stored verbatim in
   Postgres (cms_row.data).
4. A host page using the published @plasmicpkgs/plasmic-cms@0.0.335 components
   (CmsCredentialsProvider, CmsQueryRepeater, CmsRowField), opened in headless
   Chromium, executes the payloads: window.__xss = ["img-onerror","iframe-srcdoc"].
Harness sources: harness_cms.py, harness_browser.cjs, entry_browser.jsx (in this packet).

## Impact
Stored XSS in the origin of every site that renders Plasmic CMS rich-text
content with the official components. CMS content authors are typically a
lower-privileged group than the site owner/developer, so this crosses a
privilege boundary: editor-level access yields script execution for all site
visitors.

## Bounds
Requires content-author access to a CMS database (or its secret token). Sites
that sanitise CMS output themselves, or never render rich-text fields, are not
affected. The hosted plasmic.app service was not tested; the tested artefacts
are the public repository and the published npm package.

## Suggested fix
Sanitise rich-text HTML on write (server) and on render (client) with an
allow-list sanitiser, stripping event handlers, script-capable elements and
dangerous URL schemes.

Finder: FrosterDL
Vendor communication: not yet contacted. The repository has private
vulnerability reporting disabled and no SECURITY.md; the vendor's documented
security contact is security@plasmic.app (Plasmic docs, Security page).
No CVE has been assigned and this has not been submitted to another CNA.
