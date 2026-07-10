#!/usr/bin/env python3
"""数据库迁移测试 — v5.3→v6.0→v6.1→v6.2"""
import sys, os, json, tempfile, sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["SECRET_KEY"] = "sk-test-64chars-abcdef1234567890abcdef1234567890!!"
os.environ["ADMIN_PASSWORD"] = "Admin@Strong#Pass789"
os.environ["ALICE_PASSWORD"] = "Alice@Secure#Pass456"
os.environ["FLASK_HTTPS"] = "0"
os.environ["APP_ENV"] = "development"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

results = []


def test(name, ok, detail=""):
    mark = "OK" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))


print("=" * 60)
print("Database Migration Tests")
print("=" * 60)

# =============================================================
print("\n--- 1. Fresh database ---")
db_new = ROOT / "data" / "test_fresh.db"
if db_new.exists():
    db_new.unlink()

from app.database import migrate, get_db, init_db

init_db(db_path=str(db_new))
conn = get_db(str(db_new))
users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
test("2 default users created", len(users) == 2)

ver = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
test("Schema version = 7", ver == 7)

conn.execute("INSERT INTO users (username, password, email, phone, role, password_migrated) VALUES ('mig','plain123','m@t.com','555','user',1)")
conn.commit()
conn.close()

# =============================================================
print("\n--- 2. v5.3 database (no balance column) ---")
db53 = ROOT / "data" / "test_v53.db"
if db53.exists():
    db53.unlink()

conn53 = sqlite3.connect(str(db53))
conn53.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT NOT NULL, email TEXT, phone TEXT)")
conn53.execute("INSERT INTO users (username, password, email, phone) VALUES ('legacy','oldpass','legacy@x.com','111')")
conn53.execute("INSERT INTO users (username, password, email, phone) VALUES ('keep','keep123','keep@x.com','222')")
conn53.commit()
conn53.close()

init_db(db_path=str(db53))

conn = get_db(str(db53))
cols2 = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
for col in ["role", "balance_cents"]:
    test(f"v5.3→migrated has {col}", col in cols2)

users2 = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
test("v5.3 users preserved (count=2+defaults)", len(users2) >= 2)

legacy = conn.execute("SELECT * FROM users WHERE username='legacy'").fetchone()
test("legacy email preserved", legacy and legacy["email"] == "legacy@x.com")

# Password should have been migrated from plaintext
from werkzeug.security import check_password_hash
test("legacy password hash-valid", check_password_hash(legacy["password"], "oldpass"))
test("legacy password_migrated=1", legacy["password_migrated"] == 1)

bc = conn.execute("SELECT balance_cents FROM users WHERE username='legacy'").fetchone()[0]
test("legacy balance_cents = 0 (no old balance)", bc == 0)

conn.close()

# Re-migrate: idempotent
init_db(db_path=str(db53))
conn = get_db(str(db53))
users3 = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
test("Re-migration doesn't duplicate users", len(users3) == len(users2))
bc2 = conn.execute("SELECT balance_cents FROM users WHERE username='legacy'").fetchone()[0]
test("Re-migration doesn't multiply balance", bc2 == 0)
conn.close()

# =============================================================
print("\n--- 3. v6.0 database (has balance REAL) ---")
db60 = ROOT / "data" / "test_v60.db"
if db60.exists():
    db60.unlink()

conn60 = sqlite3.connect(str(db60))
conn60.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT NOT NULL, email TEXT, phone TEXT, balance REAL DEFAULT 0.0)")
conn60.execute("INSERT INTO users (username, password, email, phone, balance) VALUES ('rich','plainpwd','rich@x.com','333', 123.45)")
conn60.execute("INSERT INTO users (username, password, email, phone, balance) VALUES ('infnan','pwd123','bad@x.com','444', NULL)")
conn60.execute("INSERT INTO users (username, password, email, phone, balance) VALUES ('neg','pwd123','neg@x.com','555', -50.0)")
conn60.commit()
conn60.close()

init_db(db_path=str(db60))

conn = get_db(str(db60))
rich = conn.execute("SELECT * FROM users WHERE username='rich'").fetchone()
test("rich balance = 12345 cents", rich and rich["balance_cents"] == 12345)
test("rich password hash-valid", check_password_hash(rich["password"], "plainpwd"))

bad = conn.execute("SELECT * FROM users WHERE username='infnan'").fetchone()
test("NULL balance → 0 cents", bad and bad["balance_cents"] == 0)

neg = conn.execute("SELECT * FROM users WHERE username='neg'").fetchone()
test("negative balance → 0 cents", neg and neg["balance_cents"] == 0)

conn.close()

# Re-migrate
init_db(db_path=str(db60))
conn = get_db(str(db60))
rich2 = conn.execute("SELECT balance_cents FROM users WHERE username='rich'").fetchone()[0]
test("Re-migration doesn't double balance", rich2 == 12345)
conn.close()

# =============================================================
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")

# Cleanup
for db in [db_new, db53, db60]:
    if db.exists():
        db.unlink()

sys.exit(0 if failed == 0 else 1)
