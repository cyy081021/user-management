#!/usr/bin/env python3
"""XXE 防护测试"""
import sys, os, re, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
ADMIN_PASSWORD = os.environ.setdefault("ADMIN_PASSWORD", "Admin@Test#7890")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Test#7890")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_xxe.db")
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

print("=" * 60)
print("XXE Protection Tests")
print("=" * 60)

db = str(ROOT / "data" / "test_xxe.db")
if os.path.exists(db): os.unlink(db)

from app.database import init_db
init_db(db_path=db)
os.environ["DATABASE_PATH"] = db
from app import create_app
app = create_app()
c = app.test_client()
c.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD}, follow_redirects=True)

# =============================================================
print("\n--- 1. Normal XML accepted ---")
NORMAL_XML = "<users><user><name>Alice</name><email>a@x.com</email></user></users>"
r = c.post("/xml-import", data={"xml_data": NORMAL_XML})
body = r.data.decode()
test("normal xml parsed OK", "Alice" in body and "a@x.com" in body)

# =============================================================
print("\n--- 2. DOCTYPE / ENTITY rejected ---")
# DOCTYPE
r = c.post("/xml-import", data={"xml_data": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/hostname">]><users><user><name>&xxe;</name><email>x@x.com</email></user></users>'})
body = r.data.decode()
test("DOCTYPE rejected", "不允许" in body or "解析失败" in body)
test("secret NOT leaked (DOCTYPE)", "/etc/hostname" not in body)

# ENTITY lowercase
r = c.post("/xml-import", data={"xml_data": '<!entity xxe SYSTEM "/etc/hostname"><users><user><name>&xxe;</name><email>x@x.com</email></user></users>'})
body = r.data.decode()
test("ENTITY lowercase rejected", "不允许" in body or "解析失败" in body)

# ENTITY uppercase
r = c.post("/xml-import", data={"xml_data": '<!ENTITY xxe SYSTEM "/etc/hostname"><users><user><name>&xxe;</name><email>x@x.com</email></user></users>'})
body = r.data.decode()
test("ENTITY uppercase rejected", "不允许" in body or "解析失败" in body)

# =============================================================
print("\n--- 3. SYSTEM file path NOT read ---")
with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
    secret_path = f.name
    f.write("TOP_SECRET_XXE_VALUE_12345")

r = c.post("/xml-import", data={
    "xml_data": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{secret_path}">]><users><user><name>&xxe;</name><email>x@x.com</email></user></users>'
})
body = r.data.decode()
test("SYSTEM file NOT read", "TOP_SECRET_XXE_VALUE_12345" not in body)
os.unlink(secret_path)

# =============================================================
print("\n--- 4. Size limit ---")
r = c.post("/xml-import", data={"xml_data": "x" * 70000})
body = r.data.decode()
test("oversized XML rejected", "过大" in body or "不允许" in body)

# =============================================================
print("\n--- 5. Unauthenticated blocked ---")
db2 = str(ROOT / "data" / "test_xxe2.db")
if os.path.exists(db2): os.unlink(db2)
init_db(db_path=db2)
os.environ["DATABASE_PATH"] = db2
app2 = create_app()
c2 = app2.test_client()
r = c2.post("/xml-import", data={"xml_data": NORMAL_XML})
test("unauthenticated blocked", r.status_code != 200)

# =============================================================
print("\n--- 6. Deleted user session blocked ---")
# Register, login, delete, then try to access
db3 = str(ROOT / "data" / "test_xxe3.db")
if os.path.exists(db3): os.unlink(db3)
init_db(db_path=db3)
os.environ["DATABASE_PATH"] = db3
app3 = create_app()
c3 = app3.test_client()

c3.post("/register", data={"username": "xxe_del", "password": "DelUser@Pass99!", "email": "d@t.com", "phone": "1234567890"}, follow_redirects=True)
c3.post("/login", data={"username": "xxe_del", "password": "DelUser@Pass99!"}, follow_redirects=True)

from app.database import get_db
conn = get_db(str(db3))
conn.execute("DELETE FROM users WHERE username='xxe_del'")
conn.commit()
conn.close()

r = c3.get("/xml-import", follow_redirects=True)
body = r.data.decode()
test("deleted user redirected", "欢迎回来" not in body)

# =============================================================
print("\n--- 7. Malformed XML returns safe error ---")
r = c.post("/xml-import", data={"xml_data": "<users><user><name>X</name><email>"})
body = r.data.decode()
test("malformed XML → safe error", "解析失败" in body)
test("no Exception detail leaked", "ParseError" not in body and "Traceback" not in body)

for d in [db, db2, db3]:
    if os.path.exists(d): os.unlink(d)

print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
