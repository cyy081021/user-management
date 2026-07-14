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
ALICE_PASSWORD = os.environ["ALICE_PASSWORD"]

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

# /change-password needs CSRF and must not trust the posted username
from app.users import verify_password

r = c.post("/change-password", data={
    "username": "admin",
    "current_password": ADMIN_PASSWORD,
    "new_password": "Admin@Changed#123",
    "confirm_password": "Admin@Changed#123",
})
test("POST /change-password wo/CSRF -> 400", r.status_code == 400)
test("Admin password unchanged without CSRF", verify_password("admin", ADMIN_PASSWORD))

p3 = c.get("/profile").data.decode()
tok3 = csrf(p3)
r = c.post("/change-password", data={
    "csrf_token": tok3,
    "username": "admin",
    "current_password": ADMIN_PASSWORD,
    "new_password": "Admin@Changed#123",
    "confirm_password": "Admin@Changed#123",
}, follow_redirects=True)
test("Admin can change own password with CSRF", r.status_code == 200 and verify_password("admin", "Admin@Changed#123"))

# /logout with CSRF
p2 = c.get("/").data.decode()
tok2 = csrf(p2)
r = c.post("/logout", data={"csrf_token": tok2}, follow_redirects=True)
test("Logout with CSRF -> OK", "登录" in r.data.decode())

# Alice must not be able to change admin's password by posting username=admin
p4 = c.get("/login").data.decode()
tok4 = csrf(p4)
r = c.post("/login", data={"username": "alice", "password": ALICE_PASSWORD, "csrf_token": tok4}, follow_redirects=True)
test("Alice login with CSRF -> OK", "欢迎回来" in r.data.decode())

p5 = c.get("/profile").data.decode()
tok5 = csrf(p5)
r = c.post("/change-password", data={
    "csrf_token": tok5,
    "username": "admin",
    "current_password": ALICE_PASSWORD,
    "new_password": "Alice@Changed#123",
    "confirm_password": "Alice@Changed#123",
}, follow_redirects=True)
test("Alice change-password request succeeds for herself", r.status_code == 200 and verify_password("alice", "Alice@Changed#123"))
test("Alice cannot change admin via username field", verify_password("admin", "Admin@Changed#123") and not verify_password("admin", "Alice@Changed#123"))

if db.exists(): db.unlink()
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
