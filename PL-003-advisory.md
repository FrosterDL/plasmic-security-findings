# Advisory paste — PL-003 (GHSA-shaped; HELD PRIVATELY — plasmicapp/plasmic has private vulnerability reporting disabled and no SECURITY.md; do not submit on GitHub)

Title: Unauthenticated file upload to public asset storage — script-bearing SVG via /api/v1/image/upload and arbitrary HTML via /api/v1/cmse/file-upload

Ecosystem / package: Other / Plasmic platform server (plasmicapp/plasmic, platform/wab)
Affected versions: master @ 7d66db54ef6090b504b5ff4d920328b6701237e9
Patched versions: None
Severity: Moderate–High (provisional)
Weakness: CWE-862, CWE-434, CWE-79

## Summary
POST /api/v1/image/upload and POST /api/v1/cmse/file-upload perform no
authentication or authorization and store attacker files in the public asset
bucket (public-read), returning public URLs. The first stores SVG files
verbatim (script included) as image/svg+xml; the second derives the stored
content type from the client-declared mimetype, allowing arbitrary HTML
hosting as text/html on the asset origin.

## Details
- routes/image.ts uploadImage never checks the caller; downscaleImage passes
  SVG through unsanitised; cdn/images.ts uploadFileToS3 stores with
  ACL public-read and an explicit image/svg+xml type.
- routes/cmse.ts cmsFileUpload never calls userDbMgr/getUser (all sibling
  handlers do). Its upload() helper trusts the multipart mimetype;
  uploadDataUriToS3 with imageOnly:false accepts it, and uploadFileToS3 falls
  back to that mimetype when no magic bytes are detected.

## Proof of concept
Local deployment (WAB + Postgres, S3 endpoint configured):
1. No session, only the public anonymous CSRF token:
   curl -F 'file=@evil.svg;type=image/svg+xml' /api/v1/image/upload
   → 200 {"dataUri":"https://site-assets.plasmic.app/<md5>.svg", ...};
   the object is stored byte-identical (SVG contains
   <script>alert(document.domain)</script>) and served as image/svg+xml.
2. No session, no CSRF token:
   curl -F 'file=@phish.html;type=text/html' /api/v1/cmse/file-upload
   → 200 with a public URL; the object is stored byte-identical and served
   as text/html.
Harness source: harness_p02_uploads.py (in this packet), 4/4 checks pass.
The local storage layer was a test double (s3mock.py); handlers, typing, ACL
and URL construction are the product's code. Without S3 configured, the same
anonymous requests fail only at the AWS credentials step.

## Impact
Stored script execution in the asset origin, phishing/malware hosting on a
trusted Plasmic asset domain, and unauthenticated storage abuse.

## Bounds
Requires asset storage to be configured (true of any functional deployment).
SVG executes in the asset origin rather than the Studio origin unless assets
are served from the application domain. Hosted service not tested.

## Suggested fix
Authenticate both endpoints (and require CMS/workspace permission for
file-upload); sanitise or neutralise SVG; never trust the client mimetype;
serve uploads from a cookieless domain.

Finder: FrosterDL
Vendor communication: not yet contacted. The repository has private
vulnerability reporting disabled and no SECURITY.md; the vendor's documented
security contact is security@plasmic.app (Plasmic docs, Security page).
No CVE has been assigned and this has not been submitted to another CNA.
