#!/usr/bin/env python3
"""Minimal S3 mock for local repro: PutObject + multipart Upload flow + GetObject.
Stores objects under /tmp/s3mock-store/<bucket>/<key> with content-type sidecar.
Ignores auth/signatures (test double for the storage layer only)."""
import os, re, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STORE = "/tmp/s3mock-store"
os.makedirs(STORE, exist_ok=True)
uploads = {}  # uploadId -> {bucket,key,parts:{n:(etag,path)}}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _path(self):
        u = urllib.parse.urlparse(self.path)
        parts = u.path.lstrip("/").split("/", 1)
        bucket = parts[0] if parts else ""
        key = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
        return bucket, key, urllib.parse.parse_qs(u.query)
    def _send_xml(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())
    def do_PUT(self):
        bucket, key, q = self._path()
        length = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(length)
        if "partNumber" in q and "uploadId" in q:
            uid = q["uploadId"][0]; pn = int(q["partNumber"][0])
            d = os.path.join(STORE, ".parts", uid); os.makedirs(d, exist_ok=True)
            open(os.path.join(d, str(pn)), "wb").write(data)
            etag = f'"etag-{uid}-{pn}"'
            uploads.setdefault(uid, {"bucket": bucket, "key": key, "parts": {}})["parts"][pn] = etag
            self.send_response(200); self.send_header("ETag", etag); self.send_header("Content-Length", "0"); self.end_headers()
            return
        dest = os.path.join(STORE, bucket, key)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        open(dest, "wb").write(data)
        open(dest + ".ctype", "w").write(self.headers.get("Content-Type") or "application/octet-stream")
        self.send_response(200); self.send_header("ETag", '"etag-put"'); self.send_header("Content-Length", "0"); self.end_headers()
    def do_POST(self):
        bucket, key, q = self._path()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "uploads" in q:
            uid = "mock-upload-1"
            uploads[uid] = {"bucket": bucket, "key": key, "parts": {},
                            "ctype": self.headers.get("Content-Type") or "application/octet-stream"}
            self._send_xml(200, f"<InitiateMultipartUploadResult><Bucket>{bucket}</Bucket><Key>{key}</Key><UploadId>{uid}</UploadId></InitiateMultipartUploadResult>")
            return
        if "uploadId" in q:
            uid = q["uploadId"][0]
            info = uploads.get(uid, {"bucket": bucket, "key": key, "parts": {}})
            d = os.path.join(STORE, ".parts", uid)
            data = b""
            for pn in sorted(info["parts"], key=int):
                data += open(os.path.join(d, str(pn)), "rb").read()
            dest = os.path.join(STORE, info["bucket"], info["key"])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            open(dest, "wb").write(data)
            # Content-Type was captured from the CreateMultipartUpload request.
            open(dest + ".ctype", "w").write(info.get("ctype", "application/octet-stream"))
            loc = f"http://localhost:4569/{info['bucket']}/{info['key']}"
            self._send_xml(200, f"<CompleteMultipartUploadResult><Location>{loc}</Location><Bucket>{info['bucket']}</Bucket><Key>{info['key']}</Key><ETag>\"etag-complete\"</ETag></CompleteMultipartUploadResult>")
            return
        self._send_xml(400, "<Error><Code>NotImplemented</Code></Error>")
    def do_GET(self):
        bucket, key, q = self._path()
        dest = os.path.join(STORE, bucket, key)
        if os.path.isfile(dest):
            data = open(dest, "rb").read()
            ct = open(dest + ".ctype").read() if os.path.isfile(dest + ".ctype") else "application/octet-stream"
            self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(data))); self.end_headers()
            self.wfile.write(data)
        else:
            self._send_xml(404, "<Error><Code>NoSuchKey</Code></Error>")
    def do_HEAD(self):
        bucket, key, q = self._path()
        dest = os.path.join(STORE, bucket, key)
        if os.path.isfile(dest):
            self.send_response(200); self.send_header("Content-Length", str(os.path.getsize(dest))); self.end_headers()
        else:
            self.send_response(404); self.end_headers()
    def do_DELETE(self):
        self.send_response(204); self.end_headers()

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 4569), H).serve_forever()
