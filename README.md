# 用户信息管理平台

一个基于 Flask 的简易用户管理平台，具备完整的登录/登出、用户信息展示功能，并经过多轮安全加固。

---

## 📋 功能

- 用户登录 / 登出
- 用户信息展示（用户名、邮箱、手机、角色、余额）
- 健康检查端点 `/health`

## 🛡️ 安全特性

| 措施 | 说明 |
|------|------|
| 密码 PBKDF2 哈希存储 | 使用 `werkzeug.security` 安全哈希，不存明文 |
| 密码从环境变量读取 | 源码中无任何硬编码密码 |
| CSRF 防护 | Flask-WTF 全局 CSRF 保护 |
| 速率限制 | 单 IP 每分钟最多 10 次登录尝试 |
| 防用户枚举 | 登录失败随机延迟 0.5~1.5 秒 |
| 安全响应头 | HSTS、X-Frame-Options、CSP 等 6 个安全头 |
| Session 安全 | HttpOnly + SameSite=Lax |
| Debug 模式 | 默认关闭，需显式环境变量开启 |
| HTTPS 支持 | 可选自签名证书启用 HTTPS |

## 🚀 快速开始

### 前置条件

- Python 3.8+
- pip

### 安装

```bash
git clone git@github.com:cyy081021/user-management.git
cd user-management
```

### 配置密码

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑 .env 文件，设置管理员和用户密码
# ADMIN_PASSWORD="your_admin_password"
# ALICE_PASSWORD="your_alice_password"
```

### 启动

```bash
# 方式 1：使用启动脚本
./run.sh

# 方式 2：直接运行
export ADMIN_PASSWORD="your_pass"
export ALICE_PASSWORD="your_pass"
python3 app.py
```

### 访问

打开浏览器访问 `http://localhost:5000`

**默认账号：**
- 管理员：`admin`（密码在 `.env` 中设置）
- 普通用户：`alice`（密码在 `.env` 中设置）

## 🏭 生产部署

### Gunicorn

```bash
# HTTP
./run.sh prod

# HTTPS
./run.sh gunicorn-ssl
```

### Nginx 反向代理（推荐）

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📁 项目结构

```
├── app.py                  # Flask 主应用
├── run.sh                  # 启动脚本（4 种模式）
├── gunicorn_config.py      # Gunicorn 生产配置
├── .env.example            # 环境变量模板
├── .gitignore
├── ssl/
│   └── cert.pem            # SSL 自签名证书
├── templates/
│   ├── base.html           # 基础模板
│   ├── index.html          # 首页
│   └── login.html          # 登录页
└── static/
    └── css/
        └── style.css       # 样式文件
```

## 📊 漏洞修复记录

| 轮次 | 修复数量 | 说明 |
|:---:|:--------:|------|
| 第 1 轮 | 4 个高危 | 明文密码、页面泄漏密码、弱 secret_key、Debug 模式 |
| 第 2 轮 | 6 个中低危 | CSRF、速率限制、HTTPS、防枚举、安全响应头、调试注释 |
| 第 3 轮 | 1 个中危 | 密码从环境变量读取，移除源码硬编码 |

详见 `security_fix_report.md`

## 🖥️ 开发环境

本项目的虚拟机 IP：`192.168.163.133:5000`

---

**注意：** 本项目使用自签名 SSL 证书，仅用于开发和演示。生产环境请使用 Let's Encrypt 等可信证书。
