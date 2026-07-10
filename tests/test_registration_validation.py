#!/usr/bin/env python3
"""注册字段校验测试"""
import sys, os, sqlite3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Strong#Pass789")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Secure#Pass456")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_regval.db")
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

print("=" * 60)
print("Registration Validation Tests")
print("=" * 60)

db = ROOT / "data" / "test_regval.db"
if db.exists(): db.unlink()

from app.database import init_db
init_db()

from app import create_app
app = create_app(); c = app.test_client()

def reg(username, password, email, phone):
    return c.post("/register", data={"username": username, "password": password,
                  "email": email, "phone": phone}, follow_redirects=True)

def reg_fails(user, pw="NewUser@Pass#123", email="ok@test.com", phone="1234567890"):
    r = reg(user, pw, email, phone)
    ok = "注册失败" in r.data.decode() or "用户名" in r.data.decode() or "密码" in r.data.decode()
    # Also verify no DB record
    conn = __import__("app.database", fromlist=["get_db"]).get_db(str(db))
    exists = conn.execute("SELECT 1 FROM users WHERE username=?", (user.strip(),)).fetchone()
    conn.close()
    return ok and not exists

def reg_ok(user, pw="NewUser@Pass#123", email="ok@test.com", phone="1234567890"):
    r = reg(user, pw, email, phone)
    return "注册成功" in r.data.decode()

print("\n--- 1. Username validation ---")
test("empty username rejected", reg_fails(""))
test("2-char username rejected", reg_fails("ab", pw="Abcd@1234!Test"))
test("over-32 username rejected", reg_fails("a" * 33, pw="Abcd@1234!Test"))
test("username with spaces rejected", reg_fails("bad user", pw="Abcd@1234!Test"))
test("username with slash rejected", reg_fails("bad/user", pw="Abcd@1234!Test"))
test("username with html tag rejected", reg_fails("<script>", pw="Abcd@1234!Test"))
test("valid username accepted", reg_ok("valid_user1"))

print("\n--- 2. Email validation ---")
test("no-at email rejected", reg_fails("valid2", email="notanemail"))
test("valid email accepted", reg_ok("valid_email_user", email="real@example.com"))

print("\n--- 3. Phone validation ---")
test("abc phone rejected", reg_fails("valid3", phone="abc"))
test("valid phone accepted", reg_ok("valid_phone_user", phone="+8613800138000"))

print("\n--- 4. Successful registration can login ---")
r = c.post("/login", data={"username": "valid_user1", "password": "NewUser@Pass#123"}, follow_redirects=True)
test("valid_user1 can login", "欢迎回来" in r.data.decode())

if db.exists(): db.unlink()
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
