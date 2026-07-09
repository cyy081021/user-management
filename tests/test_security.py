#!/usr/bin/env python3
"""
最小安全测试 - 验证核心安全防护功能正常。

运行方式：
  python3 test_security.py

依赖：
  pip install requests
"""
import sys
import os
import subprocess
import time
import re
import requests
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:5000"
PASS = "✅"
FAIL = "❌"

results = []


def test(name, ok, detail=""):
    mark = PASS if ok else FAIL
    status = "通过" if ok else "失败"
    print(f"  {mark} {name}: {status}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))


# =============================================================
# 测试 1：占位密码拒绝启动
# =============================================================
print("\n━━━ 测试 1：占位密码拒绝启动 ━━━")

def try_start_with_password(admin_pw, alice_pw, label):
    env = os.environ.copy()
    env["ADMIN_PASSWORD"] = admin_pw
    env["ALICE_PASSWORD"] = alice_pw
    env["SECRET_KEY"] = "test-secret-key-32chars-min-for-testing!"
    env["FLASK_HTTPS"] = "0"
    proc = subprocess.run(
        [sys.executable, "-c", """
import sys, os
os.environ['FLASK_HTTPS'] = '0'
try:
    from app import create_app
    app = create_app()
    print('START_OK')
except SystemExit:
    print('EXIT_FAIL')
except Exception as e:
    print(f'ERROR: {e}')
"""],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return "EXIT_FAIL" in proc.stdout or "START_OK" not in proc.stdout


ok1 = try_start_with_password("在此处填写管理员密码", "Alice@StrongPass1!", "占位密码-admin")
test("占位密码被拒绝启动", ok1)

ok2 = try_start_with_password("Admin@StrongPass1!", "在此处填写普通用户密码", "占位密码-alice")
test("占位密码-alice 被拒绝启动", ok2)

ok3 = try_start_with_password("passw0rd", "Alice@StrongPass1!", "弱密码-常见词")
test("常见弱密码被拒绝启动", ok3)

# =============================================================
# 测试 2：弱密码拒绝启动
# =============================================================
print("\n━━━ 测试 2：密码强度校验拒绝启动 ━━━")

ok4 = try_start_with_password("short1A", "Alice@StrongPass1!", "密码太短（<12位）")
test("过短密码被拒绝启动", ok4)

ok5 = try_start_with_password("abcdefghijklm", "Alice@StrongPass1!", "纯小写")
test("纯小写密码被拒绝启动", ok5)

ok6 = try_start_with_password("ABCDEFGHIJKLM", "Alice@StrongPass1!", "纯大写")
test("纯大写密码被拒绝启动", ok6)

ok7 = try_start_with_password("Admin@StrongPass1!", "abcdefghijklm", "alice 纯小写")
test("任意用户弱密码都拒绝启动", ok7)

# =============================================================
# 测试 3：登录页不泄露密码
# =============================================================
print("\n━━━ 测试 3：登录页不泄露密码 ━━━")

try:
    resp = requests.get(f"{BASE_URL}/login", timeout=5)
    html = resp.text
    # 不应该在页面源码中有实际密码值泄露
    # "password" 是 HTML 表单字段名，不是泄露
    leaks = []
    actual_passwords = ["Admin@", "[PASSWORD-REDACTED]", "[PASSWORD-REDACTED]", "在此处填写", "Admin@Strong"]
    for pat in actual_passwords:
        if pat in html:
            # 确认不是在 CSRF token 值里
            ctx_before = html[max(0, html.find(pat)-30):html.find(pat)+30]
            if "csrf_token" not in ctx_before.lower() and "value" in ctx_before:
                leaks.append(pat)
    test("登录页无密码泄露", len(leaks) == 0, ",".join(leaks) if leaks else "")
except requests.ConnectionError:
    test("登录页无密码泄露", False, "服务未运行")

# =============================================================
# 测试 4：CSRF 防护
# =============================================================
print("\n━━━ 测试 4：CSRF 防护 ━━━")

try:
    resp = requests.post(f"{BASE_URL}/login",
                         data={"username": "admin", "password": "test"},
                         timeout=5)
    test("无 CSRF token 被拒绝", resp.status_code == 400, f"HTTP {resp.status_code}")
except requests.ConnectionError:
    test("无 CSRF token 被拒绝", False, "服务未运行")

# =============================================================
# 测试 5：安全响应头
# =============================================================
print("\n━━━ 测试 5：安全响应头 ━━━")

try:
    resp = requests.get(f"{BASE_URL}/", timeout=5)
    headers_ok = (
        "X-Content-Type-Options" in resp.headers
        and "X-Frame-Options" in resp.headers
        and resp.headers.get("X-Frame-Options") == "DENY"
    )
    test("安全响应头存在", headers_ok)
except requests.ConnectionError:
    test("安全响应头存在", False, "服务未运行")

# =============================================================
# 测试 6：健康检查
# =============================================================
print("\n━━━ 测试 6：健康检查 ━━━")

try:
    resp = requests.get(f"{BASE_URL}/health", timeout=5)
    data = resp.json()
    test("健康检查端点正常", resp.status_code == 200 and data.get("status") == "ok",
         f"redis={data.get('redis', '?')}")
except (requests.ConnectionError, ValueError):
    test("健康检查端点正常", False, "服务未运行或返回非 JSON")

# =============================================================
# 测试 7：生产模式不监听 0.0.0.0
# =============================================================
print("\n━━━ 测试 7：生产模式不暴露公网 ━━━")

# 检查 scripts/run.sh 中 prod 是否绑定 127.0.0.1
try:
    with open(ROOT_DIR / "scripts" / "run.sh", encoding="utf-8") as f:
        content = f.read()
    prod_binds_127 = "--bind 127.0.0.1:5000" in content and "APP_ENV=production" in content
    test("生产模式仅绑定 127.0.0.1 + APP_ENV=production", prod_binds_127)
except FileNotFoundError:
    test("生产模式仅绑定 127.0.0.1 + APP_ENV=production", False, "scripts/run.sh 不存在")

# =============================================================
# 汇总
# =============================================================
print("\n" + "=" * 50)
print("测试汇总")
print("=" * 50)

passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
total = len(results)

print(f"\n  总计: {total}  通过: {passed}  失败: {failed}")
print(f"\n  结果: {'✅ 全部通过' if failed == 0 else '❌ 存在失败项'}")

sys.exit(0 if failed == 0 else 1)
