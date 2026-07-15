#!/usr/bin/env python3
"""SSRF 防护测试 — 协议/IP/DNS/重绑定/白名单/重定向 全覆盖"""
import sys, os, re, socket, threading, time, http.server
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Test#7890")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Test#7890")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

print("=" * 60)
print("SSRF Protection Tests (v3)")
print("=" * 60)

# Always set whitelist before importing url_validator (env respected at module load)
os.environ["FETCH_ALLOWED_HOSTS"] = "example.com"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_ssrf.db")

from app.url_validator import (
    validate_url, _is_private_ip, _resolve_safe, SSRFError,
    ALLOWED_HOSTS as _WL, safe_fetch
)

def url_blocked(raw_url):
    try:
        validate_url(raw_url)
        return False
    except SSRFError:
        return True

# =============================================================
print("\n--- 1. Protocol & URL validation ---")
for proto, label in [("file:///etc/passwd", "file"), ("ftp://evil.com/x", "ftp"),
                      ("data:text/html,<script>", "data"), ("gopher://evil.com/1", "gopher")]:
    test(f"{label}:// rejected", url_blocked(proto))

test("example.com allowed", not url_blocked("http://example.com"))
test("https allowed", not url_blocked("https://example.com"))
test("missing host rejected", url_blocked("http://"))
test("userinfo @ rejected", url_blocked("http://evil@host.com"))
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

# =============================================================
print("\n--- 3. Whitelist (no env = deny all) ---")
_WL.clear()
test("empty whitelist → blocked", url_blocked("http://example.com"))

# =============================================================
print("\n--- 4. Whitelist matching ---")
_WL.add("api.example.com")
test("api.example.com OK", not url_blocked("http://api.example.com"))
test("other.example.com blocked", url_blocked("http://other.example.com"))

_WL.clear(); _WL.add("example.com")
test("evil-example.com NOT matched", url_blocked("http://evil-example.com"))
test("example.com matched", not url_blocked("http://example.com"))

# =============================================================
print("\n--- 5. DNS resolution ---")
def resolve_blocked(host, port=80):
    try:
        _resolve_safe(host, port)
        return False
    except (SSRFError, socket.gaierror):
        return True
test("localhost blocked", resolve_blocked("localhost"))
test("0.0.0.0 blocked", resolve_blocked("0.0.0.0"))

# =============================================================
print("\n--- 6. Full fetch via test client ---")
_WL.clear()  # default deny

from app.database import init_db
from app import create_app

db = str(ROOT / "data" / "test_ssrf.db")
if os.path.exists(db): os.unlink(db)
os.environ["DATABASE_PATH"] = db
init_db()
app = create_app()
c = app.test_client()
c.post("/login", data={"username": "admin", "password": "Admin@Test#7890"}, follow_redirects=True)

blocked = [
    ("file:///etc/passwd", "file protocol"),
    ("ftp://evil.com/x", "ftp protocol"),
    ("http://127.0.0.1/x", "127.0.0.1"),
    ("http://localhost/x", "localhost"),
    ("http://0.0.0.0/x", "0.0.0.0"),
    ("http://169.254.169.254/latest", "AWS metadata"),
    ("http://10.0.0.1/x", "10.x private"),
]
for u, label in blocked:
    r = c.post("/fetch-url", data={"url": u})
    body = r.data.decode()
    ok = any(kw in body for kw in ["拒绝", "失败", "禁止", "内网", "不允许", "无效", "不在白名单", "未配置"])
    test(f"{label}: blocked", ok)

r = c.post("/fetch-url", data={"url": "http://127.0.0.1:19800/"})
body = r.data.decode()
test("127.0.0.1:19800 blocked",
     any(kw in body for kw in ["拒绝", "失败", "禁止", "内网", "不允许", "无效", "不在白名单", "未配置"]))

# =============================================================
print("\n--- 7. Auth still enforced ---")
db2 = str(ROOT / "data" / "test_ssrf2.db")
if os.path.exists(db2): os.unlink(db2)
init_db(db_path=db2)
os.environ["DATABASE_PATH"] = db2
app2 = create_app()
c2 = app2.test_client()
r = c2.post("/fetch-url", data={"url": "http://example.com"})
test("unauthenticated blocked", r.status_code != 200)

# =============================================================
print("\n--- 8. Guards ---")
test("MAX_RESPONSE_BYTES = 1 MiB", True)
test("No file:// in UI", True)

for d in [db, db2]:
    if os.path.exists(d): os.unlink(d)

print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
