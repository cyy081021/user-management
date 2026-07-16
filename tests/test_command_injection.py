#!/usr/bin/env python3
"""命令注入防护测试 — /ping 路由"""
import sys, os, subprocess
from unittest.mock import patch, MagicMock
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", "sk-test-64chars-xxx-yyy-zzz-abcdef1234567890!!")
os.environ.setdefault("ADMIN_PASSWORD", "Admin@Test#7890")
os.environ.setdefault("ALICE_PASSWORD", "Alice@Test#7890")
os.environ["FLASK_HTTPS"] = "0"; os.environ["APP_ENV"] = "development"
os.environ["DATABASE_PATH"] = str(ROOT / "data" / "test_cmd_inj.db")
os.environ["WTF_CSRF_ENABLED"] = "0"
os.environ["REDIS_URL"] = "redis://127.0.0.1:6379/0"

results = []
def test(name, ok, detail=""):
    m = "OK" if ok else "FAIL"
    print(f"  [{m}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

print("=" * 60)
print("Command Injection Protection Tests")
print("=" * 60)

db = str(ROOT / "data" / "test_cmd_inj.db")
if os.path.exists(db): os.unlink(db)

from app.database import init_db
init_db(db_path=db)
os.environ["DATABASE_PATH"] = db
from app import create_app
app = create_app()
c = app.test_client()
c.post("/login", data={"username": "admin", "password": "Admin@Test#7890"}, follow_redirects=True)

# =============================================================
print("\n--- 1. Valid IPs accepted ---")
valid_ips = ["127.0.0.1", "8.8.8.8", "::1", "2001:db8::1"]
for ip in valid_ips:
    with patch("subprocess.check_output", return_value=b"PING ok\n") as mock_run:
        r = c.post("/ping", data={"ip": ip})
        body = r.data.decode()
        called = mock_run.called
        if called:
            args = mock_run.call_args[0][0]
            shell = mock_run.call_args[1].get("shell", None)
            is_list = isinstance(args, list)
            has_str = not any(cmd in str(args) for cmd in [";", "&&", "|", "`", "$("])
            test(f"{ip}: called as list, shell=False",
                 called and is_list and shell is False,
                 f"args={args[:2] if is_list else 'str'}")
        else:
            test(f"{ip}: subprocess called", called)

# =============================================================
print("\n--- 2. Command injection payloads blocked ---")
payloads = [
    "127.0.0.1;id",
    "127.0.0.1 && whoami",
    "127.0.0.1 | cat /etc/passwd",
    "127.0.0.1`whoami`",
    "127.0.0.1$(whoami)",
    "127.0.0.1\nwhoami",
    "127.0.0.1\rwhoami",
    "127.0.0.1 %26%26 whoami",
    ";id",
    "&& whoami",
    "-c 100 127.0.0.1",
]
for payload in payloads:
    with patch("subprocess.check_output", return_value=b"") as mock_run:
        r = c.post("/ping", data={"ip": payload})
        body = r.data.decode()
        blocked = r.status_code == 400 or "无效" in body
        not_called = not mock_run.called
        test(f"{payload[:35]}: blocked=400 subprocess_uncalled",
             blocked and not_called,
             f"status={r.status_code} called={mock_run.called}")

# =============================================================
print("\n--- 3. Non-IP inputs blocked ---")
non_ips = ["google.com", "hello", "", "   "]
for inp in non_ips:
    with patch("subprocess.check_output", return_value=b"") as mock_run:
        r = c.post("/ping", data={"ip": inp})
        blocked = r.status_code != 200 or not mock_run.called
        test(f"{inp or '(empty)'}: subprocess not called",
             not mock_run.called,
             f"status={r.status_code}")

# =============================================================
print("\n--- 4. Unauthenticated blocked ---")
db2 = str(ROOT / "data" / "test_cmd_inj2.db")
if os.path.exists(db2): os.unlink(db2)
init_db(db_path=db2)
os.environ["DATABASE_PATH"] = db2
app2 = create_app()
c2 = app2.test_client()
r = c2.post("/ping", data={"ip": "8.8.8.8"})
test("unauthenticated redirected", r.status_code != 200)

for d in [db, db2]:
    if os.path.exists(d): os.unlink(d)

print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
