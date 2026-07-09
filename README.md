# 用户信息管理平台

一个基于 Flask 的用户管理平台，具备用户注册、登录/登出、用户信息展示和搜索功能。

所有 SQL 查询使用参数化查询，防止 SQL 注入。

## 📋 功能

| 功能 | 路由 | 说明 |
|------|------|------|
| 用户注册 | `GET/POST /register` | 写入 SQLite `users` 表（参数化查询） |
| 用户登录 | `GET/POST /login` | 密码 PBKDF2 哈希校验 |
| 用户搜索 | `GET /search` 或 `/?keyword=` | 模糊匹配用户名/邮箱（参数化查询） |
| 上传头像 | `GET/POST /upload` | 图片上传（内容校验/Pillow重编码/UUID存储/受控访问） |
| 用户信息 | `GET /` | 展示当前用户信息 |
| 健康检查 | `GET /health` | Redis 状态检查 |

## 目录结构

```
user-management/
├── app/                          # 应用核心
│   ├── __init__.py               # 应用工厂
│   ├── routes.py                 # HTTP 路由
│   ├── auth.py                   # 认证逻辑
│   ├── security.py               # 安全工具
│   ├── users.py                  # 内存用户数据
│   └── database.py               # SQLite 数据库操作
├── wsgi.py                       # WSGI 入口
├── templates/                    # Jinja2 模板
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   └── register.html
├── static/
│   └── css/
│       └── style.css
├── tests/
│   └── test_security.py          # 安全测试
├── data/                         # SQLite 数据库文件
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

# 确保 Redis 在运行
redis-server --daemonize yes

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
- 渐进延迟：登录失败越多等待越久（1s→60s），按 IP+用户名分桶，不暴露锁定状态
- 防用户枚举随机延迟
- Session 安全（HttpOnly + SameSite + Secure）
- 安全响应头（HSTS、CSP、Cache-Control 等）
- 生产模式仅绑定 127.0.0.1
- 生产模式下强制 SECRET_KEY 配置
- Server 头不暴露版本信息
- Git 历史已清除泄露密码（filter-repo）

详见 [docs/security/security-fix-report.md](docs/security/security-fix-report.md)

## 📦 依赖

见 [requirements.txt](requirements.txt)，核心依赖：

- Flask 3.1、Werkzeug 3.1、Flask-WTF、Flask-Limiter
- Redis、Gunicorn、SQLite3、Pillow、python-magic

## 🔖 版本历史

| 版本 | 说明 |
|:----:|------|
| v5.3 | 修复上传安全交付问题（依赖/路径穿越/炸弹防护/CI/jpeg） |
| v5.2 | 深度加固文件上传安全（内容校验/重编码/受控访问） |
| v5.1 | 修复文件上传漏洞（后缀白名单 + 防路径穿越） |
| v5.0 | 新增头像上传功能 + 修复 SQL 注入 |
| v4.1 | 安全审计修复（渐进延迟/SECRET_KEY/明文清除） |
| v4.0 | 模块化重构（app/ 包拆分） |
| v3.0 | 12 项安全加固改进 |
| v2.0 | 密码移入环境变量 |
| v1.0 | 初始安全加固 |

## 🏭 生产部署

```bash
./scripts/run.sh prod
# 配合 Nginx 反代（参考 deployment/nginx.conf.example）
```

## 🤝 报告安全漏洞

请参阅 [SECURITY.md](SECURITY.md)
