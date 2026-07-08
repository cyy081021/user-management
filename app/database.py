"""
数据库模块 — SQLite 操作（演示用，含 SQL 注入漏洞）
"""
import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")


def get_db():
    """获取数据库连接"""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库和表，插入默认用户"""
    conn = get_db()
    cursor = conn.cursor()

    # 创建 users 表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)

    # 插入默认用户（使用 INSERT OR IGNORE 防止重复）
    default_users = [
        ("admin", "admin123", "admin@example.com", "13800138000"),
        ("alice", "alice2025", "alice@example.com", "13900139001"),
    ]
    for u, p, e, ph in default_users:
        cursor.execute(
            f"INSERT OR IGNORE INTO users (username, password, email, phone) "
            f"VALUES ('{u}', '{p}', '{e}', '{ph}')"
        )

    conn.commit()
    conn.close()
    print("[数据库] 初始化完成，默认用户已插入")
