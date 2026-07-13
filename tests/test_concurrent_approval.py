#!/usr/bin/env python3
"""并发审批 & 角色撤销 & HTTP路由并发测试"""
import sys, os, sqlite3, threading, time, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Strong#Pass789")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Secure#Pass456")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/0")

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

def csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""

print("=" * 60)
print("Concurrent Approval & Route Tests")
print("=" * 60)

db = ROOT / "data" / "test_conc2.db"
if db.exists(): db.unlink()
os.environ["DATABASE_PATH"] = str(db)

from app.database import init_db, get_db
init_db()

# Create pending order for alice
conn = get_db(str(db))
conn.execute("INSERT INTO recharge_orders(transaction_id,user_id,amount_cents,status) VALUES('tx-01',2,700,'pending')")
conn.commit()
conn.close()

# =============================================================
print("\n--- 1. SQL-level concurrent (BEGIN EXCLUSIVE) ---")
results_conc = []
def do_sql_approve(name):
    try:
        c = sqlite3.connect(str(db)); c.row_factory = sqlite3.Row
        c.execute("BEGIN EXCLUSIVE"); time.sleep(0.01)
        o = c.execute("SELECT id,status FROM recharge_orders WHERE id=1").fetchone()
        if not o or o["status"]!="pending": c.rollback(); c.close(); results_conc.append((name,"skipped")); return
        cur = c.execute("UPDATE recharge_orders SET status='approved' WHERE id=1 AND status='pending'")
        if cur.rowcount!=1: c.rollback(); c.close(); results_conc.append((name,"race_lost")); return
        c.execute("UPDATE users SET balance_cents=balance_cents+700 WHERE id=2")
        c.commit(); c.close(); results_conc.append((name,"approved"))
    except Exception as e: results_conc.append((name,f"error:{e}"))
t1=threading.Thread(target=do_sql_approve,args=("t1",)); t2=threading.Thread(target=do_sql_approve,args=("t2",))
t1.start(); t2.start(); t1.join(); t2.join()
approved_sql = sum(1 for r in results_conc if r[1]=="approved")
test("SQL concurrent: only 1 approved", approved_sql==1)
conn = get_db(str(db))
bal = conn.execute("SELECT balance_cents FROM users WHERE id=2").fetchone()[0]; conn.close()
test(f"SQL balance=700 (not 1400)", bal==700)

# =============================================================
print("\n--- 2. HTTP route concurrent ---")
# Reset
conn = get_db(str(db)); conn.execute("UPDATE recharge_orders SET status='pending',approved_by=NULL WHERE id=1")
conn.execute("UPDATE users SET balance_cents=0 WHERE id=2"); conn.commit(); conn.close()

from app import create_app
os.environ["DATABASE_PATH"] = str(db)
results_http = []

def do_http_approve(name):
    try:
        app2 = create_app(); c2 = app2.test_client()
        c2.post("/login", data={"username":"admin","password":"Admin@Strong#Pass789"}, follow_redirects=True)
        p = c2.get("/profile").data.decode()
        r = c2.post("/admin/approve_recharge", data={"order_id":"1","csrf_token":csrf(p)})
        results_http.append((name, r.status_code))
    except Exception as e: results_http.append((name, f"error:{e}"))

t3=threading.Thread(target=do_http_approve,args=("http-t1",)); t4=threading.Thread(target=do_http_approve,args=("http-t2",))
t3.start(); t4.start(); t3.join(); t4.join()
one_ok = sum(1 for r in results_http if r[1] in (200,302))
one_409 = sum(1 for r in results_http if r[1]==409)
test(f"HTTP concurrent: one OK ({one_ok}) one 409 ({one_409})", one_ok==1 and one_409==1)

conn = get_db(str(db))
final_bal = conn.execute("SELECT balance_cents FROM users WHERE id=2").fetchone()[0]
final_status = conn.execute("SELECT status,approved_by FROM recharge_orders WHERE id=1").fetchone()
conn.close()
test(f"HTTP final balance=700", final_bal==700)
test("HTTP order approved once", final_status["status"]=="approved" and final_status["approved_by"] is not None)

# =============================================================
print("\n--- 3. Search access control ---")
app = create_app(); c = app.test_client()
c.post("/login", data={"username":"alice","password":"Alice@Secure#Pass456"}, follow_redirects=True)
r = c.get("/search?keyword=admin"); body = r.data.decode()
test("Alice search hides admin email", "admin@example.com" not in body)
test("Alice search hides admin phone", "13800138000" not in body)

from app.users import get_safe_user_info
info = get_safe_user_info("admin")
test("get_safe_user_info no password", info and "password" not in info)

if db.exists(): db.unlink()
print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
