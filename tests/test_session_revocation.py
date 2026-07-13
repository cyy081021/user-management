#!/usr/bin/env python3
"""Session撤销测试"""
import sys, os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Strong#Pass789")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Secure#Pass456")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_sessrev.db")
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

print("=" * 60)
print("Session Revocation Tests")
print("=" * 60)

db = ROOT / "data" / "test_sessrev.db"
if db.exists(): db.unlink()

from app.database import init_db, get_db
init_db()

from app import create_app
app = create_app(); c = app.test_client()

# Register user
c.post("/register", data={"username": "delete_me", "password": "Delete@Pass123!", "email": "d@t.com", "phone": "1380000111"}, follow_redirects=True)
# Login
c.post("/login", data={"username": "delete_me", "password": "Delete@Pass123!"}, follow_redirects=True)
r = c.get("/", follow_redirects=True)
test("user logged in", "欢迎回来" in r.data.decode())
r = c.get("/upload")
test("can access /upload", r.status_code == 200)

# Delete from DB
conn = get_db(str(db))
conn.execute("DELETE FROM users WHERE username='delete_me'")
conn.commit()
conn.close()

# Verify session revoked
r = c.get("/upload", follow_redirects=True)
test("/upload rejected after deletion", "欢迎回来" not in r.data.decode())
r = c.get("/profile", follow_redirects=True)
test("/profile rejected after deletion", "欢迎回来" not in r.data.decode())
r = c.get("/search?keyword=a", follow_redirects=True)
test("/search rejected after deletion", "欢迎回来" not in r.data.decode())

# Admin deletion test
c.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD}, follow_redirects=True)
conn = get_db(str(db))
conn.execute("UPDATE users SET role='user' WHERE username='admin'")
conn.commit()
conn.close()
r = c.post("/admin/approve_recharge", data={"order_id": "1"})
test("demoted admin gets 403", r.status_code == 403)

if db.exists(): db.unlink()
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
