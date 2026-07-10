#!/usr/bin/env python3
"""密码轮换测试"""
import sys, os, sqlite3, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("FLASK_HTTPS", "0")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/0")
os.environ["WTF_CSRF_ENABLED"] = "0"

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

print("=" * 60)
print("Password Rotation Tests")
print("=" * 60)

db = ROOT / "data" / "test_pw_rotate.db"
if db.exists(): db.unlink()

from app.database import init_db, get_db
from app.users import verify_password

os.environ["DATABASE_PATH"] = str(db)

# Round 1: old password
init_db(admin_pw="Admin@OldStrong#1", alice_pw="Alice@OldStrong#1")
test("R1: old admin pw works", verify_password("admin", "Admin@OldStrong#1"))
test("R1: old alice pw works", verify_password("alice", "Alice@OldStrong#1"))

# Register normal user
conn = get_db(str(db))
from werkzeug.security import generate_password_hash
conn.execute("INSERT INTO users(username,password,email,phone,role,password_migrated) VALUES(?,?,?,?,'user',1)",
             ("keepme", generate_password_hash("KeepMe@Pass#99"), "k@x.com", "1234567"))
conn.commit()
conn.close()

# Round 2: new password
init_db(admin_pw="Admin@NewStrong#2", alice_pw="Alice@NewStrong#2")
test("R2: old admin pw FAILS", not verify_password("admin", "Admin@OldStrong#1"))
test("R2: new admin pw works", verify_password("admin", "Admin@NewStrong#2"))
test("R2: old alice pw FAILS", not verify_password("alice", "Alice@OldStrong#1"))
test("R2: new alice pw works", verify_password("alice", "Alice@NewStrong#2"))

# Normal user unchanged
test("R2: normal user pw unchanged", verify_password("keepme", "KeepMe@Pass#99"))

# Round 3: same pw again (idempotent)
init_db(admin_pw="Admin@NewStrong#2", alice_pw="Alice@NewStrong#2")
test("R3: same pw still works (admin)", verify_password("admin", "Admin@NewStrong#2"))
test("R3: same pw still works (alice)", verify_password("alice", "Alice@NewStrong#2"))

if db.exists(): db.unlink()
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
