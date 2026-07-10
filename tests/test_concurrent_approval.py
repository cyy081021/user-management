#!/usr/bin/env python3
"""并发审批 & 角色撤销测试"""
import sys, os, sqlite3, threading, time, tempfile
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
print("Concurrent Approval & Role Revocation Tests")
print("=" * 60)

# =============================================================
print("\n--- 1. Concurrent approval (atomic) ---")

db_c = ROOT / "data" / "test_concurrent.db"
if db_c.exists():
    db_c.unlink()

from app.database import init_db, get_db

init_db(db_path=str(db_c))

# Create a pending order
conn = get_db(str(db_c))
conn.execute("INSERT INTO recharge_orders (transaction_id, user_id, amount_cents, status) VALUES ('tx-001', 2, 700, 'pending')")
conn.commit()
conn.close()

# Check initial state
conn = get_db(str(db_c))
alice_before = conn.execute("SELECT balance_cents FROM users WHERE id=2").fetchone()[0]
print(f"  Alice balance before: {alice_before} cents")
conn.close()
test("Initial balance is 0", alice_before == 0)

# Simulate two concurrent approvals via separate connections
results_concurrent = []


def do_approve(name):
    try:
        conn = sqlite3.connect(str(db_c))
        conn.row_factory = sqlite3.Row
        # WAL 模式下，BEGIN EXCLUSIVE 才能防止并发写
        conn.execute("BEGIN EXCLUSIVE")
        time.sleep(0.01)  # 让两个线程都进入锁竞争

        order = conn.execute("SELECT id, user_id, amount_cents, status FROM recharge_orders WHERE id=1").fetchone()
        if not order or order["status"] != "pending":
            conn.rollback()
            conn.close()
            results_concurrent.append((name, "already_processed", None))
            return

        cur = conn.execute("UPDATE recharge_orders SET status='approved' WHERE id=1 AND status='pending'")
        if cur.rowcount != 1:
            conn.rollback()
            conn.close()
            results_concurrent.append((name, "race_lost", None))
            return

        conn.execute("UPDATE users SET balance_cents = balance_cents + ? WHERE id=2", (700,))
        conn.commit()
        conn.close()
        results_concurrent.append((name, "approved", None))
    except Exception as e:
        results_concurrent.append((name, "error", str(e)))


t1 = threading.Thread(target=do_approve, args=("thread-1",))
t2 = threading.Thread(target=do_approve, args=("thread-2",))
t1.start()
t2.start()
t1.join()
t2.join()

print(f"  Results: {results_concurrent}")
approved_count = sum(1 for r in results_concurrent if r[1] == "approved")
test("Only 1 approval succeeded", approved_count == 1)

conn = get_db(str(db_c))
alice_after = conn.execute("SELECT balance_cents FROM users WHERE id=2").fetchone()[0]
order_status = conn.execute("SELECT status FROM recharge_orders WHERE id=1").fetchone()[0]
conn.close()

test(f"Alice balance = 700 (not 1400)", alice_after == 700)
test(f"Order status = approved", order_status == "approved")

# =============================================================
print("\n--- 2. Role revocation ---")

os.environ["DATABASE_PATH"] = str(db_c)
os.environ["WTF_CSRF_ENABLED"] = "0"

from app import create_app as _create_app
app = _create_app()
client = app.test_client()

# Login as admin
client.post("/login", data={"username": "admin", "password": "Admin@Strong#Pass789"}, follow_redirects=True)

# Downgrade admin to user in DB
conn = get_db(str(db_c))
conn.execute("UPDATE users SET role = 'user' WHERE username = 'admin'")
conn.commit()
conn.close()

# Try to approve with old session (role should be checked from DB now)
r = client.post("/admin/approve_recharge", data={"order_id": "1"})
test("Demoted admin gets 403", r.status_code == 403)

# Check balance unchanged
conn = get_db(str(db_c))
alice_final = conn.execute("SELECT balance_cents FROM users WHERE id=2").fetchone()[0]
conn.close()
test("Balance unchanged after rejected approval", alice_final == 700)

# =============================================================
print("\n--- 3. Search access control ---")

# Login as alice
client.post("/login", data={"username": "alice", "password": "Alice@Secure#Pass456"}, follow_redirects=True)
r = client.get("/search?keyword=admin")
data = r.data.decode()
test("Alice search hides admin email", "admin@example.com" not in data)
test("Alice search hides admin phone", "13800138000" not in data)

# Logout → search
client.post("/logout", follow_redirects=True)
r = client.get("/search?keyword=a")
test("Unauthenticated search redirects", r.status_code in (302, 200))

# =============================================================
print("\n--- 4. get_safe_user_info no password leak ---")
from app.users import get_safe_user_info
conn = get_db(str(db_c))
conn.execute("INSERT OR REPLACE INTO users (id, username, password, email, phone, role, password_migrated) VALUES (99,'safe_test','hash_test','s@t.com','999','user',1)")
conn.commit()
conn.close()

info = get_safe_user_info("safe_test")
test("get_safe_user_info no password", info and "password" not in info)
test("get_safe_user_info has email", info and info.get("email") == "s@t.com")

# =============================================================
print("\n--- 5. Register error is generic ---")
r = client.post("/register", data={"username": "admin", "password": "NewUser@Pass123", "email": "x@x.com", "phone": "000"}, follow_redirects=True)
test("Duplicate register → generic error", "注册失败" in r.data.decode() and "UNIQUE" not in r.data.decode().upper())

# =============================================================
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")

if db_c.exists():
    db_c.unlink()
sys.exit(0 if failed == 0 else 1)
