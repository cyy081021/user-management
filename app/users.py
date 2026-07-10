"""
用户数据模块 — 统一以 SQLite users 表为数据源
"""
from werkzeug.security import check_password_hash
from app.database import get_db


def get_user_by_username(username, db_path=None):
    """根据用户名查询用户完整信息（含密码，仅用于认证）"""
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT id, username, password, email, phone, role, balance_cents FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(uid, db_path=None):
    """根据 ID 查询用户信息（不含 password）"""
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT id, username, email, phone, role, balance_cents FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_role(uid, db_path=None):
    """返回用户当前角色（每次从 DB 读取，不依赖 session 缓存）"""
    conn = get_db(db_path)
    try:
        row = conn.execute("SELECT role FROM users WHERE id = ?", (uid,)).fetchone()
        return row["role"] if row else None
    finally:
        conn.close()


def verify_password(username, password, db_path=None):
    """验证密码"""
    user = get_user_by_username(username, db_path)
    if user:
        return check_password_hash(user["password"], password)
    return False


def get_safe_user_info(username):
    """返回不含密码的用户信息（安全版本）"""
    user = get_user_by_username(username)
    if user:
        user.pop("password", None)
    return user
