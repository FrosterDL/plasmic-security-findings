# Advisory paste — PL-004 (GHSA-shaped; HELD PRIVATELY — plasmicapp/plasmic has private vulnerability reporting disabled and no SECURITY.md; do not submit on GitHub)

Title: Default "fake" data-source operation encryption key allows unauthenticated attackers to forge operation IDs and execute arbitrary SQL with stored credentials

Ecosystem / package: Other / Plasmic platform server (plasmicapp/plasmic, platform/wab)
Affected versions: master @ 7d66db54ef6090b504b5ff4d920328b6701237e9, in deployments without a configured dataSourceOperationEncryptionKey (the default)
Patched versions: None
Severity: High (provisional)
Weakness: CWE-798, CWE-321, CWE-862

## Summary
When a Plasmic server runs without ~/.plasmic/secrets.json — the documented
default — the key used to encrypt data-source operation IDs falls back to the
literal string "fake" (server/secrets.ts getOpEncryptionKey). The stable
encryptor (server/util/crypt.ts) uses a hard-coded salt and IV, so anyone can
forge a valid opId offline for an arbitrary operation template. The public
endpoint POST /api/v1/server-data/sources/:dataSourceId/execute requires no
authentication and executes the forged operation with the data source's stored
credentials.

## Details
- secrets.ts: loadSecrets() returns {} if the file is missing; the module
  header says "Plasmic should run without any secrets.json file."
- data-source-utils.ts getDataSourceOperation: a non-UUID opId is decrypted
  with getOpEncryptionKey() and JSON-parsed into an OperationTemplate.
- server-data.ts execute handler: superDbMgr, skipPermissionCheck on the data
  source lookup; role gate passes for anonymous callers when the (forged)
  template has no roleId.
- The same "fake" fallback backs getEncryptionKey() (app end-user JWTs, OAuth
  codes) — related, not separately demonstrated here.

## Proof of concept
Local deployment with no secrets.json (verified):
1. Owner creates a Postgres data source (stored credentials) and allows a
   project to use it.
2. Controls: an owner-issued UUID opId executes unauthenticated (intended);
   an opId forged with a wrong key is rejected with 400 Invalid opId.
3. Forge offline (forge_opid.mjs, the repo's own algorithm, key "fake"):
   template {"name":"customRead","templates":{"query":"select count(*)::int as user_count from \"user\""}}
   POST /api/v1/server-data/sources/<id>/execute {"opId":<forged>,"userArgs":{}}
   with no session → 200 {"data":[{"user_count":4}], ...}.
4. Forged customWrite "create table pwned_by_forged_opid (id int, note text)"
   → 200; the table is present on direct database inspection (dropped after).
Harness source: harness_p04_pg.py + forge_opid.mjs (in this packet), 6/6 pass.

## Impact
Unauthenticated arbitrary SQL read/write against connected Postgres data
sources (and equivalent forged operations for other source types) using
stored credentials, on any deployment that did not set the optional key.

## Bounds
Default-configuration issue: deployments that set
dataSourceOperationEncryptionKey are not affected. Attacker must know a data
source ID (present in published bundles/configuration). The hosted
plasmic.app service was not tested and no claim is made about its
configuration.

## Suggested fix
Fail closed when the key is unset: generate and persist a per-deployment
random key at first run, or disable encrypted opIds; remove the "fake"
fallbacks for both operation and app-auth encryption keys.

Finder: FrosterDL
Vendor communication: not yet contacted. The repository has private
vulnerability reporting disabled and no SECURITY.md; the vendor's documented
security contact is security@plasmic.app (Plasmic docs, Security page).
No CVE has been assigned and this has not been submitted to another CNA.
