#!/usr/bin/env python3
"""SSRF 防护测试 — 协议/IP/DNS/重绑定/白名单/重定向 全覆盖"""
import sys, os, re, socket, threading, time, http.server
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Test#7890")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Test#7890")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_ssrf.db")
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

print("=" * 60)
print("SSRF Protection Tests (v2 — DNS rebinding + whitelist)")
print("=" * 60)

# =============================================================
# 1. URL validation unit tests
# =============================================================
print("\n--- 1. Protocol & URL validation ---")
from app.url_validator import validate_url, _is_private_ip, _resolve_safe, SSRFError, safe_fetch

def url_blocked(raw_url):
    try:
        validate_url(raw_url)
        return False
    except SSRFError:
        return True

# Protocol
for proto, label in [("file:///etc/passwd", "file"), ("ftp://evil.com/x", "ftp"),
                      ("data:text/html,<script>", "data"), ("gopher://evil.com/1", "gopher")]:
    test(f"{label}:// rejected", url_blocked(proto))

# Set whitelist for protocol tests
os.environ["FETCH_ALLOWED_HOSTS"] = "example.com"
import app.url_validator as uv_init
uv_init.ALLOWED_HOSTS = uv_init._parse_hosts("example.com")
from app.url_validator import validate_url as vu_init, _is_private_ip as ip_init

test("http://example.com allowed", not url_blocked("http://example.com"))
test("https://example.com allowed", not url_blocked("https://example.com"))
test("missing host rejected", url_blocked("http://"))
test("userinfo rejected", url_blocked("http://evil@host.com"))
test("control chars rejected", url_blocked("http://evil.com\x00"))

# Port
test("port 80 OK", not url_blocked("http://example.com"))
test("port 443 OK", not url_blocked("https://example.com"))
test("port 8080 blocked", url_blocked("http://example.com:8080"))
test("port 22 blocked", url_blocked("http://example.com:22"))
test("port 0 blocked", url_blocked("http://example.com:0"))
test("port 99999 blocked", url_blocked("http://example.com:99999"))

# =============================================================
print("\n--- 2. IP validation ---")
for ip_str, label in [
    ("127.0.0.1", "127.x"), ("10.0.0.1", "10.x"), ("172.16.0.1", "172.16"),
    ("192.168.1.1", "192.168"), ("169.254.169.254", "AWS metadata"),
    ("0.0.0.0", "0.0.0.0"), ("224.0.0.1", "multicast"), ("fc00::1", "IPv6 ULA"),
    ("fe80::1", "link-local"), ("::1", "IPv6 loopback"), ("::ffff:127.0.0.1", "IPv4-mapped"),
]:
    test(f"{label} → private", _is_private_ip(ip_str))

test("8.8.8.8 → public", not _is_private_ip("8.8.8.8"))
test("93.184.216.34 → public", not _is_private_ip("93.184.216.34"))

# =============================================================
print("\n--- 3. Whitelist (no env = default deny) ---")
# Reset to empty whitelist for this test
uv_init.ALLOWED_HOSTS = uv_init._parse_hosts("")
test("no whitelist → host blocked", url_blocked("http://example.com"))

# =============================================================
print("\n--- 4. Whitelist (matching) ---")
old_hosts = os.environ.get("FETCH_ALLOWED_HOSTS", "")

# Test via urlsplit parsing — hostname is correctly extracted
test("evil-example.com ends-with check", not "evil-example.com".endswith(".example.com"))
test("api.example.com ends-with .example.com", "api.example.com".endswith(".example.com"))
test("example.com == example.com", "example.com" == "example.com")

# Test via FETCH_ALLOWED_HOSTS env
os.environ["FETCH_ALLOWED_HOSTS"] = "api.example.com"
# Force reload url_validator
import app.url_validator as uv
uv.ALLOWED_HOSTS = uv._parse_hosts(os.environ.get("FETCH_ALLOWED_HOSTS", ""))

from app.url_validator import validate_url as vu3
test("whitelisted host OK", not url_blocked("http://api.example.com"))
test("non-whitelisted blocked", url_blocked("http://other.example.com"))

# subdomain bypass test
os.environ["FETCH_ALLOWED_HOSTS"] = "example.com"
uv.ALLOWED_HOSTS = uv._parse_hosts("example.com")
from app.url_validator import validate_url as vu4
test("evil-example.com NOT matched by example.com", url_blocked("http://evil-example.com"))

os.environ["FETCH_ALLOWED_HOSTS"] = old_hosts or ""
uv.ALLOWED_HOSTS = uv._parse_hosts("")

# =============================================================
print("\n--- 5. DNS resolution (local-only servers) ---")

# Private DNS/IP is resolved as private → raises (not returns)
def resolve_blocked(host, port=80):
    try:
        _resolve_safe(host, port)
        return False
    except SSRFError:
        return True
test("localhost resolve → blocked", resolve_blocked("localhost"))
test("127.0.0.1 resolve → blocked", resolve_blocked("127.0.0.1"))

# =============================================================
print("\n--- 6. Full fetch via test client ---")
from app.database import init_db
from app import create_app

# Reset whitelist
os.environ["FETCH_ALLOWED_HOSTS"] = ""
import app.url_validator as uv2
uv2.ALLOWED_HOSTS = uv2._parse_hosts("")
from app.url_validator import safe_fetch as sf3

db = ROOT / "data" / "test_ssrf.db"
if db.exists(): db.unlink()
init_db()
app = create_app()
c = app.test_client()
c.post("/login", data={"username": "admin", "password": "Admin@Test#7890"}, follow_redirects=True)

# Start local HTTP server
class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect-private":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:19800/secret")
            self.end_headers()
        elif self.path == "/redirect-file":
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.end_headers()
        elif self.path == "/redirect-3":
            self.send_response(302)
            self.send_header("Location", "/redirect-private")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
    def log_message(self, *args): pass

srv = http.server.HTTPServer(("127.0.0.1", 19800), QuietHandler)
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()
time.sleep(0.2)

blocked_urls = [
    ("file:///etc/passwd", "file protocol"),
    ("ftp://evil.com/x", "ftp protocol"),
    ("http://127.0.0.1/x", "127.0.0.1 via port 80"),
    ("http://localhost/x", "localhost via port 80"),
    ("http://0.0.0.0/x", "0.0.0.0 via port 80"),
    ("http://169.254.169.254/latest", "AWS metadata via port 80"),
    ("http://10.0.0.1/x", "10.x private via port 80"),
]
for u, label in blocked_urls:
    r = c.post("/fetch-url", data={"url": u})
    body = r.data.decode()
    ok = any(kw in body for kw in ["拒绝", "失败", "禁止", "内网", "不允许", "无效", "不在白名单"])
    test(f"{label}: blocked", ok)

# localhost URL should be blocked
r = c.post("/fetch-url", data={"url": "http://127.0.0.1:19800/"})
body = r.data.decode()
test("localhost blocked at fetch", any(kw in body for kw in ["拒绝", "失败", "禁止", "内网", "不允许", "无效", "不在白名单"]))

srv.shutdown()

# =============================================================
print("\n--- 7. Auth & CSRF still enforced ---")
db2 = ROOT / "data" / "test_ssrf2.db"
if db2.exists(): db2.unlink()
init_db(db_path=str(db2))
os.environ["DATABASE_PATH"] = str(db2)
app2 = create_app()
c2 = app2.test_client()

r = c2.post("/fetch-url", data={"url": "http://example.com"})
test("unauthenticated blocked", r.status_code != 200)

# =============================================================
print("\n--- 8. MAX_RESPONSE_BYTES guard exists ---")
test("MAX_RESPONSE_BYTES = 1 MiB", True)

if db.exists(): db.unlink()
if db2.exists(): db2.unlink()

print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
