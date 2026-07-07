# 用户信息管理平台

一个基于 Flask 的用户管理平台，具备完整的登录/登出、用户信息展示功能，并经过多轮安全加固。

---

## 📋 功能

- 用户登录 / 登出
- 用户信息展示（用户名、邮箱、手机、角色、余额）
- 健康检查端点 `/health`

## 🛡️ 安全特性

| 措施 | 说明 |
|------|------|
| 密码 PBKDF2 哈希存储 | 使用 Werkzeug 安全哈希 |
| 密码从环境变量读取 | 源码中无任何硬编码密码 |
| 启动时密码强度校验 | 不足 12 位/缺大写/缺小写/缺数字/缺特殊字符 → 拒绝启动 |
| 占位密码拒绝启动 | 包含 "在此处填写"、placeholder 等 → 拒绝启动 |
| CSRF 防护 | Flask-WTF 全局保护 |
| 速率限制 | 单 IP 每分钟最多 10 次登录，Redis 共享计数 |
| 账号临时锁定 | 连续 5 次失败 → 锁定 15 分钟 |
| 防用户枚举 | 登录失败随机延迟 0.5~1.5 秒 |
| 安全响应头 | HSTS、X-Frame-Options、CSP、Referrer-Policy 等 |
| Session 安全 | HttpOnly + SameSite=Lax + Secure(HTTPS 下) |
| Session 超时 | 2 小时自动过期 |
| 生产模式 | Gunicorn + 127.0.0.1 本地绑定需 Nginx 反代 |

## 🚀 快速开始

### 前置条件

- Python 3.8+
- Redis（限流存储）

### 安装

```bash
git clone git@github.com:cyy081021/user-management.git
cd user-management
pip install -r requirements.txt
```

### 配置密码

```bash
cp .env.example .env
# 编辑 .env，用密码管理器生成强密码填入
# 要求：≥12 位，含大写字母 + 小写字母 + 数字 + 特殊字符
```

### 启动

```bash
# 开发模式
./run.sh

# 生产模式（仅 127.0.0.1，需配置 Nginx 反代）
./run.sh prod
```

### 访问

打开浏览器访问 `http://localhost:5000`

## 🏭 生产部署

### Gunicorn + Nginx（推荐）

```bash
# 启动应用（仅监听本地）
./run.sh prod
```

```nginx
# /etc/nginx/sites-available/user-management
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate     /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### HTTPS 直连

```bash
# Flask 开发服务器
./run.sh https

# Gunicorn 生产
./run.sh gunicorn-ssl
```

## 📁 项目结构

```
├── app.py                  # Flask 主应用
├── run.sh                  # 启动脚本（4 种模式）
├── gunicorn_config.py      # Gunicorn 生产配置
├── requirements.txt        # 依赖清单
├── .env.example            # 环境变量模板
├── .gitignore
├── ssl/
│   └── cert.pem            # SSL 自签名证书
├── templates/
│   ├── base.html           # 基础模板
│   ├── index.html          # 首页
│   └── login.html          # 登录页
├── static/
│   └── css/
│       └── style.css       # 样式文件
└── security_fix_report.md  # 漏洞修复记录
```

---

**注意：** 本项目使用自签名 SSL 证书，仅用于开发和演示。生产环境请使用 Let's Encrypt 等可信证书。
