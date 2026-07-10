"""
用户数据模块 — 统一以 SQLite users 表为数据源
"""
from werkzeug.security import check_password_hash
from app.database import get_db


def get_user_by_username(username):
    """根据用户名查询用户完整信息"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, password, email, phone, role, balance_cents FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(uid):
    """根据 ID 查询用户信息（不含密码）"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, phone, role, balance_cents FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def verify_password(username, password):
    """验证密码"""
    user = get_user_by_username(username)
    if user:
        return check_password_hash(user["password"], password)
    return False


def get_safe_user_info(username):
    """返回不含密码的用户信息，兼容旧接口"""
    return get_user_by_username(username)
