# 用户信息管理平台

一个基于 Flask 的用户管理平台，具备登录/登出、用户信息展示功能，经过多轮安全加固。

## 目录结构

```
user-management/
├── app/                          # 应用核心
│   ├── __init__.py               # 应用工厂
│   ├── routes.py                 # HTTP 路由
│   ├── auth.py                   # 认证逻辑
│   ├── security.py               # 安全工具
│   └── users.py                  # 用户数据
├── wsgi.py                       # WSGI 入口
├── templates/                    # Jinja2 模板
│   ├── base.html
│   ├── index.html
│   └── login.html
├── static/
│   └── css/
│       └── style.css
├── tests/
│   └── test_security.py          # 安全测试
├── docs/security/
│   ├── security-fix-report.md
│   └── password-security-review-v3.md
├── deployment/
│   ├── gunicorn.conf.py          # Gunicorn 配置
│   ├── nginx.conf.example        # Nginx 配置模板
│   └── ssl/
│       └── cert.example.pem      # 示例 SSL 证书
├── scripts/
│   └── run.sh                    # 启动脚本
├── .github/
│   ├── workflows/tests.yml       # CI 流水线
│   └── ISSUE_TEMPLATE/security-hardening.md
├── .env.example
├── requirements.txt
├── SECURITY.md
└── LICENSE (MIT)
```

## 🚀 快速开始

```bash
git clone git@github.com:cyy081021/user-management.git
cd user-management

pip install -r requirements.txt

cp .env.example .env
# 编辑 .env，用密码管理器生成 12 位以上强密码

./scripts/run.sh
# 或
./scripts/run.sh prod    # 生产模式
```

## 🛡️ 安全特性

- 密码 PBKDF2 哈希，从环境变量读取
- 启动时强制校验密码强度（≥12位+大小写+数字+特殊字符）
- 占位密码拒绝启动
- CSRF 全局保护
- Redis 共享限流（多 worker 协同）
- 账号锁定：连续 5 次失败 → 锁定 15 分钟
- 防用户枚举随机延迟
- Session 安全（HttpOnly + SameSite + Secure）
- 安全响应头（HSTS、CSP 等 6 项）
- 生产模式仅绑定 127.0.0.1

详见 [docs/security/security-fix-report.md](docs/security/security-fix-report.md)

## 📦 依赖

见 [requirements.txt](requirements.txt)，核心依赖：

- Flask 3.1、Werkzeug 3.1、Flask-WTF、Flask-Limiter
- Redis、Gunicorn

## 🔖 版本

| 版本 | 说明 |
|:----:|------|
| v1.0 | 初始安全加固 |
| v2.0 | 密码移入环境变量 |
| v3.0 | 12 项安全改进 + 模块化重构 |

## 🏭 生产部署

```bash
./scripts/run.sh prod
# 配合 Nginx 反代（参考 deployment/nginx.conf.example）
```

## 🤝 报告安全漏洞

请参阅 [SECURITY.md](SECURITY.md)
