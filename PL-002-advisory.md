# Advisory paste — PL-002 (GHSA-shaped; HELD PRIVATELY — plasmicapp/plasmic has private vulnerability reporting disabled and no SECURITY.md; do not submit on GitHub)

Title: Email-verification bypass — GET /api/v1/auth/getEmailVerificationToken returns valid verification tokens to anonymous callers

Ecosystem / package: Other / Plasmic platform server (plasmicapp/plasmic, platform/wab)
Affected versions: master @ 7d66db54ef6090b504b5ff4d920328b6701237e9 and earlier (not bisected)
Patched versions: None
Severity: Moderate–High (provisional)
Weakness: CWE-862, CWE-200, CWE-863

## Summary
The endpoint GET /api/v1/auth/getEmailVerificationToken returns a valid
email-verification token for any registered email address to an unauthenticated
caller. An attacker can register an account under an email they do not own and
verify it without mailbox access. confirmEmail also does not verify that the
caller is the user being confirmed.

## Details
- AppServer.ts registers the route with no auth wrapper and no rate limiter
  (its siblings sendEmailVerification/confirmEmail have one).
- server/auth/routes.ts getEmailVerificationToken never checks the caller; for
  an existing user it returns mgr.createEmailVerificationForUser(user) — whose
  DbMgr implementation explicitly calls allowAnyone() — as plaintext JSON
  {status:true, token}. Non-existent emails get a decoy token.
- DbMgr.compareEmailVerificationToken (used by POST /api/v1/auth/confirmEmail)
  only requires a logged-in caller, not the owner of the email.

## Proof of concept
Local deployment of the repository (Postgres + WAB server):
1. POST /api/v1/auth/sign-up {"email":"victim-not-owned@example-corp.com",
   "password":"<attacker-chosen>", ...} → account created,
   waitingEmailVerification = true in Postgres.
2. Controls: a token minted for a non-existent email (decoy) and a wrong token
   both fail confirmEmail with InvalidToken; the flag stays true.
3. GET /api/v1/auth/getEmailVerificationToken (no session) with body
   {"email":"victim-not-owned@example-corp.com"} → returns a real token.
4. POST /api/v1/auth/confirmEmail {"email":..., "token":<minted>} from the
   attacker's session → {status:true}; waitingEmailVerification flips to false;
   GET /api/v1/auth/self returns 200 for the victim email.
Harness source: harness_p01_email_verification.py (in this packet), 7/7 checks pass.

## Impact
Verified Plasmic accounts under arbitrary unregistered email addresses
(pre-registration / impersonation), defeating the platform's email-ownership
gate for the whole API, and cross-account verification of other users' pending
accounts.

## Bounds
Target email must not already be a Plasmic user. No access to existing
accounts or passwords. The hosted service was not tested; the tested code is
the public repository.

## Suggested fix
Never return verification tokens in API responses; require account ownership
for token issuance; bind confirmEmail to the session user; rate-limit the
endpoint like its siblings.

Finder: FrosterDL
Vendor communication: not yet contacted. The repository has private
vulnerability reporting disabled and no SECURITY.md; the vendor's documented
security contact is security@plasmic.app (Plasmic docs, Security page).
No CVE has been assigned and this has not been submitted to another CNA.
