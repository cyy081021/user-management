"""
WSGI 入口 — Gunicorn / Flask 开发服务器共用

使用方式：
  gunicorn wsgi:app
  # 或
  python wsgi.py
"""
import os
import logging

logger = logging.getLogger(__name__)

from app import create_app

app = create_app()

if __name__ == "__main__":
    use_https = os.environ.get("FLASK_HTTPS", "0") == "1"
    ssl_context = None
    if use_https:
        cert, key = "/root/ssl/cert.pem", "/root/ssl/key.pem"
        if os.path.exists(cert) and os.path.exists(key):
            ssl_context = (cert, key)
            logger.info("HTTPS 已启用")
        else:
            logger.warning("SSL 证书不存在，回退 HTTP")
            use_https = False

    logger.info("启动 %s://0.0.0.0:5000", "https" if use_https else "http")
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context=ssl_context)
