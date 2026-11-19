# Advisory paste — PL-005 (GHSA-shaped; HELD PRIVATELY — plasmicapp/plasmic has private vulnerability reporting disabled and no SECURITY.md; do not submit on GitHub)

Title: Loader preview endpoints serve unpublished draft bundles to anyone holding the public project token

Ecosystem / package: Other / Plasmic platform server (plasmicapp/plasmic, platform/wab)
Affected versions: master @ 7d66db54ef6090b504b5ff4d920328b6701237e9
Patched versions: None
Severity: Moderate (provisional)
Weakness: CWE-863, CWE-200

## Summary
GET /api/v1/loader/code/preview (and the html/repr preview endpoints) return
the latest unpublished revision of a project to any caller with the project's
public API token — the credential embedded in live sites' loader
configuration. Published endpoints restrict the same token to published
versions; preview applies the same "viewer" check to draft content.

## Details
routes/loader.ts buildLatestLoaderAssets calls only
checkProjectPerms(id, "viewer", "get"). DbMgr.checkProjectPerms satisfies
"viewer" with the public projectApiToken ("Public tokens grant read access;
secret tokens grant write access"). No secret-token or membership check
exists anywhere in the preview path.

## Proof of concept
Local deployment; target project never published, invite-only:
- Control: GET /api/v1/loader/code/published?projectId=<id> with the public
  token → 400 "has not been published yet".
- Attack: GET /api/v1/loader/code/preview?projectId=<id>&loaderVersion=10
  with header "x-plasmic-api-project-tokens: <id>:<public token>"
  → 200, 108,706-byte bundle of the latest unpublished revision.
- Wrong token → 401; another project's token → 401.

## Impact
Disclosure of all unpublished project content (draft pages, unreleased copy,
branch variants, full draft model via repr-v3) to anyone holding the
low-sensitivity public token.

## Bounds and vendor-intent note
Read-only. Requires the projectId and public token. The vendor may consider
public-token read access intended; the published/preview distinction in the
product's own API is the counterpoint. Severity provisional pending vendor
triage; close as by-design if the vendor confirms intent. Hosted service not
tested.

## Suggested fix
Require the secret API token or authenticated project membership for preview
endpoints; limit the public token to published/versioned bundles.

Finder: FrosterDL
Vendor communication: not yet contacted. The repository has private
vulnerability reporting disabled and no SECURITY.md; the vendor's documented
security contact is security@plasmic.app (Plasmic docs, Security page).
No CVE has been assigned and this has not been submitted to another CNA.
