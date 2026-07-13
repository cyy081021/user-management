#!/usr/bin/env python3
"""/page 路径穿越回归测试"""
import sys, os
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

def h(response):
    return response.data.decode()

print("=" * 60)
print("Page Security Regression Tests")
print("=" * 60)

# --- Whitelist success ---
print("\n--- 1. Whitelist page success ---")
r = c.get("/page?name=help")
test("/page?name=help → 200", r.status_code == 200)
test("help returns help content", "帮助中心" in h(r))

# --- Path traversal attacks ---
print("\n--- 2. Path traversal attacks → 404 ---")
attacks = [
    "../README.md",
    "../app/routes.py",
    "../.git/config",
    "..\\README.md",
    "..\\..\\etc\\passwd",
    "/etc/passwd",
    "../../../../etc/passwd",
]
for attack in attacks:
    r = c.get(f"/page?name={attack}")
    ok = r.status_code == 404
    body = h(r)
    no_leak = "README" not in body[:200] and "SECRET_KEY" not in body[:200] and "password" not in body[:200].lower()
    test(f"{attack} → 404 no leak", ok and no_leak, f"status={r.status_code}")

# --- URL-encoded traversal ---
print("\n--- 3. URL-encoded traversal → 404 ---")
encoded = [
    "%2e%2e%2fREADME.md",
    "%2e%2e/%2e%2e/app/routes.py",
    "..%2f.git%2fconfig",
]
for attack in encoded:
    r = c.get(f"/page?name={attack}")
    test(f"{attack} → 404", r.status_code == 404, f"status={r.status_code}")

# --- Non-whitelist pages ---
print("\n--- 4. Non-whitelist → 404 ---")
r = c.get("/page?name=register")
test("register (not in whitelist) → 404", r.status_code == 404)
r = c.get("/page?name=login")
test("login → 404", r.status_code == 404)
r = c.get("/page?name=index")
test("index → 404", r.status_code == 404)

print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
if db.exists(): db.unlink()
sys.exit(0 if failed == 0 else 1)
