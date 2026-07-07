"""
WSGI 入口 — Gunicorn / Flask 开发服务器共用

使用方式：
  gunicorn wsgi:app
  # 或
  python wsgi.py

HTTPS 模式（需证书就位）：
  FLASK_HTTPS=1 python wsgi.py
  # 可通过 FLASK_SSL_CERT / FLASK_SSL_KEY 指定证书路径
"""
import os
import sys
import logging

# ---------------------------------------------------------------------------
# 隐藏 Server 头中的版本信息（安全：防止攻击者针对性利用已知 CVE）
# ---------------------------------------------------------------------------
from werkzeug.serving import WSGIRequestHandler

WSGIRequestHandler.server_version = "UserManagement"
WSGIRequestHandler.sys_version = ""  # 不暴露 Python 版本

logger = logging.getLogger(__name__)

from app import create_app

app = create_app()

if __name__ == "__main__":
    use_https = os.environ.get("FLASK_HTTPS", "0") == "1"
    ssl_context = None

    if use_https:
        cert = os.environ.get("FLASK_SSL_CERT", "/root/deployment/ssl/cert.example.pem")
        key = os.environ.get("FLASK_SSL_KEY", "/root/deployment/ssl/key.example.pem")

        if not os.path.exists(cert):
            print(f"\n❌ HTTPS 模式下证书文件不存在: {cert}")
            print(f"   请先生成自签名证书，或设置 FLASK_SSL_CERT/FLASK_SSL_KEY\n")
            sys.exit(1)
        if not os.path.exists(key):
            print(f"\n❌ HTTPS 模式下私钥文件不存在: {key}")
            print(f"   请先生成自签名私钥，或设置 FLASK_SSL_CERT/FLASK_SSL_KEY\n")
            sys.exit(1)

        ssl_context = (cert, key)
        logger.info("HTTPS 已启用 (cert=%s)", cert)

    scheme = "https" if use_https else "http"
    logger.info("启动 %s://0.0.0.0:5000", scheme)
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context=ssl_context)
