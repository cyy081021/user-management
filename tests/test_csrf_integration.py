#!/usr/bin/env python3
"""CSRF集成测试 — 验证各路由 Token 防护"""
import sys, os, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Strong#Pass789")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Secure#Pass456")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_csrf_int.db")
os.environ.pop("WTF_CSRF_ENABLED", None)  # Remove test override to use real CSRF
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

def csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""

print("=" * 60)
print("CSRF Integration Tests")
print("=" * 60)

db = ROOT / "data" / "test_csrf_int.db"
if db.exists(): db.unlink()

from app.database import init_db
init_db()

# Force real CSRF
from app import create_app
app = create_app()
c = app.test_client()

# --- Without tokens ---
print("\n--- 1. Routes without CSRF token ---")
tests = [
    ("/login", "post", {"username": "a", "password": "b"}),
    ("/register", "post", {"username": "a2", "password": "X@12345678901"}),
    ("/logout", "post", {}),
]
for path, method, data in tests:
    r = c.post(path, data=data)
    test(f"POST {path} wo/CSRF -> 400", r.status_code == 400)

# Login first for protected routes
p = c.get("/login").data.decode()
tok = csrf(p)
r = c.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD, "csrf_token": tok}, follow_redirects=True)
test("Login with CSRF -> OK", "欢迎回来" in r.data.decode())

# /recharge needs CSRF
r = c.post("/recharge", data={"amount": "10"})
test("POST /recharge wo/CSRF -> 400", r.status_code == 400)

# /admin/approve_recharge needs CSRF
r = c.post("/admin/approve_recharge", data={"order_id": "1"})
test("POST /admin/approve_recharge wo/CSRF -> 400", r.status_code == 400)

# /logout with CSRF
p2 = c.get("/").data.decode()
tok2 = csrf(p2)
r = c.post("/logout", data={"csrf_token": tok2}, follow_redirects=True)
test("Logout with CSRF -> OK", "登录" in r.data.decode())

if db.exists(): db.unlink()
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
