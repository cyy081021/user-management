"""
Gunicorn 生产配置

使用方式：
  gunicorn -c deployment/gunicorn.conf.py wsgi:app
"""
import os
import multiprocessing

# 绑定地址
bind = "0.0.0.0:5000"

# 工作进程数（推荐 CPU 核心数 × 2 + 1）
workers = multiprocessing.cpu_count() * 2 + 1

# 工作模式
worker_class = "sync"

# 超时设置
timeout = 30
keepalive = 5

# 日志
accesslog = "/var/log/user-mgmt/access.log"
errorlog = "/var/log/user-mgmt/error.log"
loglevel = "info"

# 守护进程
daemon = False

# 隐藏 Server 头中的版本信息
server_name = "UserManagement"
# 禁用 gunicorn 版本在 Server 头中暴露
# (配合 wsgi.py 中的 WSGIRequestHandler monkey-patch 共同生效)
os.environ["SERVER_SOFTWARE"] = "UserManagement"

# SSL（可选）
# certfile = "/path/to/cert.pem"
# keyfile = "/path/to/key.pem"
