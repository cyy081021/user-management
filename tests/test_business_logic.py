#!/usr/bin/env python3
"""Business logic security tests — v6.1"""
import sys, os, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["SECRET_KEY"] = "sk-test-64chars-abcdef1234567890abcdef1234567890!!"
os.environ["ADMIN_PASSWORD"] = "Admin@Strong#Pass789"
os.environ["ALICE_PASSWORD"] = "Alice@Secure#Pass456"
os.environ["FLASK_HTTPS"] = "0"
os.environ["APP_ENV"] = "development"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

from app import create_app
from app.database import get_db, init_db

app = create_app()
app.config["WTF_CSRF_ENABLED"] = False
client = app.test_client()
client.testing = True

results = []

def test(name, ok, detail=""):
    mark = "OK" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

def h(r):
    return r.data.decode()

print("=" * 60)
print("Business Logic Security Tests")
print("=" * 60)

# Clean DB
dbp = ROOT / "data" / "users.db"
if dbp.exists():
    dbp.unlink()
init_db(admin_pw="Admin@Strong#Pass789", alice_pw="Alice@Secure#Pass456")

print("\n--- 1. Registration & Login ---")
r = client.post("/register", data={"username": "newuser", "password": "NewUser@Pass123", "email": "n@t.com", "phone": "111"}, follow_redirects=True)
test("Register success", "注册成功" in h(r))

# Login as new user
client.post("/login", data={"username": "newuser", "password": "NewUser@Pass123"}, follow_redirects=True)
r = client.get("/", follow_redirects=True)
test("New user can login", "欢迎回来" in h(r))

# Check password is hashed
conn = get_db()
pwd_row = conn.execute("SELECT password FROM users WHERE username='newuser'").fetchone()
conn.close()
test("Password is hashed", pwd_row and "NewUser@Pass123" not in pwd_row["password"])

print("\n--- 2. Profile IDOR ---")
# Login as alice
client.post("/login", data={"username": "alice", "password": "Alice@Secure#Pass456"}, follow_redirects=True)
r = client.get("/profile?user_id=1")
test("Alice cannot view admin profile (403)", r.status_code == 403)

r = client.get("/profile")
test("Alice can view own profile", r.status_code == 200 and "alice" in h(r))

r = client.get("/profile?user_id=999")
test("Non-existent user returns 403/404", r.status_code in (403, 404))

# Admin can view others
client.post("/login", data={"username": "admin", "password": "Admin@Strong#Pass789"}, follow_redirects=True)
r = client.get("/profile?user_id=2")
test("Admin can view other users", r.status_code == 200 and "alice" in h(r))

print("\n--- 3. Recharge Security ---")
client.post("/login", data={"username": "alice", "password": "Alice@Secure#Pass456"}, follow_redirects=True)

def charge(amount):
    return client.post("/recharge", data={"amount": str(amount)}, follow_redirects=True)

tests = [
    (-50, "Negative rejected", "大于"),
    (0, "Zero rejected", "大于"),
    ("nan", "NaN rejected", "有限"),  # nan is_finite=False → "必须为有限数字"
    ("inf", "Inf rejected", "有限"),
    ("1e309", "1e309 rejected", "超过"),  # 1e309 > 10000, 走"不超过"校验
    (20000, ">10000 rejected", "超过"),
    (1.234, "Three decimals rejected", "小数"),
]
for val, label, kw in tests:
    r = charge(val)
    test(label, kw in h(r))

r = charge(50.00)
test("Legal amount creates pending order", "等待管理员审批" in h(r))

r = client.get("/profile")
test("Balance unchanged after pending", "0.00" in h(r))

print("\n--- 4. Admin Approval ---")
# Non-admin
client.post("/login", data={"username": "alice", "password": "Alice@Secure#Pass456"}, follow_redirects=True)
r = client.post("/admin/approve_recharge", data={"order_id": "1"})
test("Non-admin rejected (403)", r.status_code == 403)

# Admin approves
client.post("/login", data={"username": "admin", "password": "Admin@Strong#Pass789"}, follow_redirects=True)
r = client.post("/admin/approve_recharge", data={"order_id": "1"}, follow_redirects=True)
test("Admin approval succeeds", r.status_code == 200)

conn = get_db()
bal = conn.execute("SELECT balance_cents FROM users WHERE id=2").fetchone()
conn.close()
test("Alice balance increased by 5000 cents", bal and bal["balance_cents"] == 5000)

r = client.post("/admin/approve_recharge", data={"order_id": "1"})
test("Double approval rejected (400)", r.status_code == 400)

print("\n--- 5. Balance Consistency ---")
client.post("/login", data={"username": "alice", "password": "Alice@Secure#Pass456"}, follow_redirects=True)
r = client.get("/")
test("Homepage shows balance 50.00", "50.00" in h(r))
r = client.get("/profile")
test("Profile shows balance 50.00", "50.00" in h(r))

print("\n--- 6. Logout ---")
client.post("/login", data={"username": "admin", "password": "Admin@Strong#Pass789"}, follow_redirects=True)
r = client.get("/")
# Logout via POST
client.post("/logout", follow_redirects=True)
r = client.get("/")
test("Logout clears session", "请先登录" in h(r))

r = client.get("/profile")
test("Cannot access profile after logout", "请先登录" in h(r) or r.status_code == 302)

print("\n--- 7. Register then login (v2) ---")
client.post("/login", data={"username": "newuser", "password": "NewUser@Pass123"}, follow_redirects=True)
r = client.get("/")
test("Registered user can login", "欢迎回来" in h(r))

print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
