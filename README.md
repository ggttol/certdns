# CertDNS · 证书与多云 DNS 解析管理中心

通过 Docker Compose 编排运行的轻量级 TLS 证书与多账户阿里云 DNS 管理台。单静态 Go 二进制内置 ACME DNS-01 签发引擎、续期调度、多云 DNS 管理与零外部前端构建依赖的原生 ES 模块控制台。

## 核心特性

1. **多阿里云账户支持（中国站 / 国际站 / 自定义接入点）**：
   - **阿里云中国站 (`cn`)**：默认 `https://alidns.aliyuncs.com/`，`RegionId=cn-hangzhou`。
   - **阿里云国际站 (`intl`)**：默认 `https://alidns.ap-southeast-1.aliyuncs.com/`，`RegionId=ap-southeast-1`，`Lang=en`。
   - **自定义接入点 (`custom`)**：支持自定义任意地域 Endpoint 与 RegionId。
   - **跨账户自动路由签发**：多域名证书可自动匹配各域名所属阿里云账户完成 DNS-01 验证，支持失败自动清理与中断任务优雅重入队。
2. **安全加固与静态凭据加密**：
   - `secretbox` 使用 AES-256-GCM（自动维护 `0600` `secret.key` 或通过 `CERTDNS_SECRET_KEY` 注入）对阿里云 `AccessKey Secret` 与 `Webhook URL` 加密存储。
   - `__Host-certdns_session` 会话 Cookie、`Sec-Fetch-Site` 同源校验、严格 CSP（零内联样式与内联脚本）、按客户端 IP 隔离登录限流与双栈 SSRF 防护。
3. **多用户 RBAC 与远程节点证书拉取 (Pull API)**：
   - `admin` / `operator` / `viewer` 三级角色权限隔离，内置最后一名启用管理员保护。
   - 为边缘节点签发最小权限 Bearer Token，提供支持 RFC 9110 `ETag`/`304` 与全 SAN 授权校验的 `/api/v1/pull/certificates` 及 `/api/v1/pull/certificates/{domain}` 接口。
4. **增强型证书、DNS 与安全审计**：
   - 支持 `EC256`、`EC384`、`RSA2048`、`RSA4096` 签发，外部 PEM 证书校验导入，Nginx / Apache / 全量 ZIP 导出及在线复制。
   - 支持 DNS 记录增删改查、单条暂停/启用、备注管理、入口域名防误删告警与标准 BIND `.zone` 导出。
   - 内置动作分类与关键字过滤的 `audit_logs` 审计日志，以及兼容钉钉、飞书、企业微信、Slack 的 Webhook 告警推送。

## 环境变量

可通过项目根目录 `.env` 文件或容器环境变量注入：

| 变量名 | 默认值 | 说明 |
|---|---|---|
| `CERTDNS_DATA` | `/data` | SQLite 数据库、密钥与证书存储目录（自动收紧为 `0700`） |
| `CERTDNS_TLS_DIR` | `/data/tls` | 导出给 Nginx 的管理入口证书目录 |
| `CERTDNS_LISTEN` | `:9080` | HTTP 监听地址 |
| `CERTDNS_HOSTNAME` | `cert.example.com` | 管理台入口域名（同时请同步修改 `deploy/nginx.conf` 中的 `server_name`） |
| `CERTDNS_SECRET_KEY` | 空（使用 `/data/secret.key`） | 可选外部注入的 32 字节主密钥（64 位 Hex 或 Base64） |
| `CERTDNS_ALLOW_PRIVATE_WEBHOOK` | `0` | 设为 `1` 时允许向内网地址发送 Webhook |
| `CERTDNS_INSECURE_COOKIE` | `0` | 仅本地 HTTP 调试时设为 `1` |

## 快速部署与运维命令

```bash
# 1. 配置管理入口域名（并同步修改 deploy/nginx.conf 中的 cert.example.com）
echo "CERTDNS_HOSTNAME=cert.example.com" > .env

# 2. 构建并启动服务
docker compose up -d --build

# 3. 查看初始管理员 (admin) 密码（首次初始化自动生成）
cat ./data/admin-password

# 4. 查看容器状态与实时日志
docker compose ps
docker compose logs -f app
docker compose logs -f nginx
```
