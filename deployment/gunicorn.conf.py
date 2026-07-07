"""
Gunicorn 生产配置

使用方式：
  gunicorn -c gunicorn_config.py app:app
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

# SSL（可选，启用后 Flask 层不再需要 ssl_context）
# certfile = "/root/ssl/cert.pem"
# keyfile = "/root/ssl/key.pem"
