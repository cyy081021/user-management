"""
用户数据模块 — USERS 字典（密码以 PBKDF2 哈希存储）
"""
from werkzeug.security import generate_password_hash

USERS = {}


def _init_users(admin_pw, alice_pw):
    USERS.clear()
    USERS.update({
        "admin": {
            "username": "admin",
            "password": generate_password_hash(admin_pw),
            "role": "admin",
            "email": "admin@example.com",
            "phone": "13800138000",
            "balance": 99999,
        },
        "alice": {
            "username": "alice",
            "password": generate_password_hash(alice_pw),
            "role": "user",
            "email": "alice@example.com",
            "phone": "13900139001",
            "balance": 100,
        },
    })


def get_safe_user_info(username):
    """返回不包含密码字段的用户信息"""
    user = USERS.get(username)
    if user:
        info = user.copy()
        info.pop("password", None)
        return info
    return None


def verify_password(username, password):
    """验证用户密码"""
    user = USERS.get(username)
    if user:
        from werkzeug.security import check_password_hash
        return check_password_hash(user["password"], password)
    return False
