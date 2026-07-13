#!/usr/bin/env python3
"""/page 路径穿越 & 文件包含回归测试"""
import sys, os, urllib.parse
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Strong#Pass789")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Secure#Pass456")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_page_sec.db")
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

from app import create_app
from app.database import init_db

db = ROOT / "data" / "test_page_sec.db"
if db.exists(): db.unlink()

init_db()
app = create_app()
c = app.test_client()

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

def h(r): return r.data.decode()

print("=" * 60)
print("Page Security Regression Tests")
print("=" * 60)

# --- Whitelist ---
print("\n--- 1. Whitelist page ---")
r = c.get("/page?name=help")
test("/page?name=help → 200", r.status_code == 200)
test("help page contains content", "帮助" in h(r))

# --- Path traversal ---
print("\n--- 2. Path traversal → 404 ---")
attacks = [
    "../README.md", "../app/routes.py", "../app/__init__.py",
    "../.git/config", "../.env", "../SECURITY.md",
    "..\\README.md", "..\\..\\etc\\passwd",
    "/etc/passwd", "/etc/shadow",
    "../../../../etc/passwd",
    "....//....//etc/passwd",
]
for a in attacks:
    r = c.get(f"/page?name={a}")
    body = h(r)
    no_leak = "SECRET" not in body[:300] and "password" not in body[:300].lower() \
        and "README" not in body[:200] and "app/routes" not in body[:200]
    test(f"{a} → 404 no leak", r.status_code == 404 and no_leak, f"s={r.status_code}")

# --- URL encoding ---
print("\n--- 3. URL encoding → 404 ---")
encoded = [
    "%2e%2e%2fREADME.md",
    "%2e%2e/%2e%2e/app/routes.py",
    "..%2f.git%2fconfig",
    "%252e%252e%252fREADME.md",  # double encoding
    f"{urllib.parse.quote('../')}app/routes.py",
]
for a in encoded:
    r = c.get(f"/page?name={a}")
    body = h(r)
    no_leak = "SECRET" not in body[:300] and "routes" not in body[:200]
    test(f"{a[:40]} → 404", r.status_code == 404 and no_leak, f"s={r.status_code}")

# --- Non-whitelist ---
print("\n--- 4. Non-whitelist → 404 ---")
for name in ["help.html", "register", "login", "index", "admin", "file:///etc/passwd",
             "https://example.com/file", ""]:
    r = c.get(f"/page?name={name}")
    test(f"{name or '(empty)'} → 404", r.status_code == 404)

# --- No reading registered user data ---
print("\n--- 5. No info leak in error/404 responses ---")
r = c.get("/page?name=../app/routes.py")
assert "SECRET_KEY" not in h(r)[:300] and "ADMIN_PASSWORD" not in h(r)[:300]
test("No SECRET_KEY leaked in 404 response", True)
test("No ADMIN_PASSWORD leaked in 404 response", True)

if db.exists(): db.unlink()
print("\n--- Summary ---")
p = sum(1 for _,ok in results if ok)
f = sum(1 for _,ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {p}  Failed: {f}")
sys.exit(0 if f == 0 else 1)
