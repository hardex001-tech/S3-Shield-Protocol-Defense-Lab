"""
vulnerable_origin.py
--------------------
Simulates a standard HTTP Origin / S3 Bucket Server that implements RFC 7233
HTTP Byte-Range requests (HTTP 206 Partial Content with multipart/byteranges)
and serves static small images without protocol-level hardening.

Demonstrates WHY the 4 AlienVault OTX 'BotnetExposer' attacks are dangerous:
  1. HTTP range in small image (S3#): A tiny 1,500-byte PNG image requested with
     250 overlapping byte ranges ('Range: bytes=0-1,0-2,...,0-250') forces the
     server to allocate 250 MIME multipart boundaries, amplifying a 1.3KB request
     into a ~34KB response (~25x-80x bandwidth & CPU amplification).
  2. Open of aggressive number of TCP connections: Exhausts worker threads.
  3. Rogue Robot (S3#): Scrapes endpoints nonstop with empty/rogue User-Agent.
  4. Searching for sensitive file or directory: Exposes /.env.backup & /admin/db.bkp.
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import re
from typing import List, Tuple

# A realistic 1,500-byte small PNG image payload hosted on the origin server
SMALL_IMAGE_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa"
    + (b"S3_STATIC_SMALL_IMAGE_PIXEL_DATA_" * 44)
    + b"IEND\xaeB`\x82"
)[:1500]

SENSITIVE_FILES_MOCK = {
    "/.env.backup": b"APP_ENV=production\nDB_HOST=10.0.4.19\nDB_PASS=super_secret_prod_991\n",
    "/admin/db_backup.bkp": b"-- SQL DUMP\nCREATE TABLE users (id INT, email VARCHAR(255));\n",
    "/backup.zip": b"PK\x03\x04_MOCK_ARCHIVE_PAYLOAD"
}


def parse_byte_ranges(range_header: str, file_size: int) -> List[Tuple[int, int]]:
    """
    Standard RFC 7233 Range parser (unhardened — allows unlimited overlapping ranges,
    which is the exact vulnerability abused in 'HTTP range in small image').
    """
    if not range_header.startswith("bytes="):
        return []
    ranges = []
    parts = range_header[len("bytes="):].split(",")
    for part in parts:
        part = part.strip()
        m = re.match(r"^(\d+)-(\d*)$", part)
        if not m:
            continue
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else file_size - 1
        if 0 <= start <= end < file_size:
            ranges.append((start, end))
    return ranges


class VulnerableOriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Silence noisy default stdout logging during benchmarks
        pass

    def do_GET(self):
        path = self.path.split("?")[0]

        # 1. Vulnerable Small Image Endpoint (supports unrestricted HTTP Range headers)
        if path in ("/assets/small_logo.png", "/small.png"):
            range_hdr = self.headers.get("Range")
            if range_hdr:
                ranges = parse_byte_ranges(range_hdr, len(SMALL_IMAGE_BYTES))
                if ranges:
                    if len(ranges) == 1:
                        start, end = ranges[0]
                        chunk = SMALL_IMAGE_BYTES[start:end + 1]
                        self.send_response(206, "Partial Content")
                        self.send_header("Content-Type", "image/png")
                        self.send_header("Accept-Ranges", "bytes")
                        self.send_header("Content-Range", f"bytes {start}-{end}/{len(SMALL_IMAGE_BYTES)}")
                        self.send_header("Content-Length", str(len(chunk)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(chunk)
                        return
                    else:
                        # Multipart byteranges amplification vulnerability!
                        # Every tiny 2-byte range gets wrapped in a ~135-byte MIME boundary header.
                        boundary = "multipart_s3_byterange_boundary_9918273"
                        body_parts = []
                        for start, end in ranges:
                            chunk = SMALL_IMAGE_BYTES[start:end + 1]
                            part_hdr = (
                                f"--{boundary}\r\n"
                                f"Content-Type: image/png\r\n"
                                f"Content-Range: bytes {start}-{end}/{len(SMALL_IMAGE_BYTES)}\r\n\r\n"
                            ).encode("ascii")
                            body_parts.append(part_hdr + chunk + b"\r\n")
                        body_parts.append(f"--{boundary}--\r\n".encode("ascii"))
                        full_payload = b"".join(body_parts)

                        self.send_response(206, "Partial Content")
                        self.send_header("Content-Type", f"multipart/byteranges; boundary={boundary}")
                        self.send_header("Accept-Ranges", "bytes")
                        self.send_header("Content-Length", str(len(full_payload)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(full_payload)
                        return

            # Normal full image response
            self.send_response(200, "OK")
            self.send_header("Content-Type", "image/png")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(len(SMALL_IMAGE_BYTES)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(SMALL_IMAGE_BYTES)
            return

        # 2. Unprotected Sensitive Backup Files (Vulnerable to Directory/File Enumeration)
        if path in SENSITIVE_FILES_MOCK:
            payload = SENSITIVE_FILES_MOCK[path]
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            return

        # 3. Default Application Page
        payload = b'{"status":"ok","service":"origin-s3-static-server"}'
        self.send_response(200, "OK")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


def start_origin_server(host: str = "127.0.0.1", port: int = 9001) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), VulnerableOriginHandler)
    return server


if __name__ == "__main__":
    srv = start_origin_server()
    print("[Origin] Vulnerable Origin Server listening on http://127.0.0.1:9001")
    srv.serve_forever()
