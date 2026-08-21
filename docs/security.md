# 安全模型与约定

## 设计目标

| 目标 | 做法 |
|------|------|
| 不明文落盘 | `vault.bin`：Argon2id 派生密钥 + AES-256-GCM |
| 不进 git | 仓库只保留 secret **名称**；忽略 `vault.bin` / `token` / `master.pass` / `.env` |
| 不进 CI/agent 源码 | 用 `jinteng run` 运行时注入环境变量 |
| LAN 统一 | `serve` + Bearer Token；客户端不持有 master password |

## 两把钥匙

| 密钥 | 谁持有 | 用途 |
|------|--------|------|
| **Master password** | 仅服务端（或本机直连 CLI） | 解密 `vault.bin` |
| **API Token** (`jt_…`) | 服务端 + 受信任客户端 | 调用 `/v1/*` |

客户端 **不要** 分发 master password。Token 泄露后：在服务端 `jinteng token rotate`，更新各客户端。

## 信任边界

- 默认 **HTTP + Bearer**，假定链路在可信局域网（或 VPN）内。
- **不要**把 `8787` 裸暴露到公网。
- 需要远程时：WireGuard/Tailscale，或 Caddy/Nginx 做 HTTPS 并限制来源 IP。

## 文件权限建议

```text
$JINTENG_DIR/          0700
  vault.bin             0600
  token                 0600
  master.pass           0600
```

Docker：`deploy/secrets/master.pass` 勿提交（已有 `deploy/secrets/.gitignore`）。

## 运维注意

- `jinteng get` / API GET 会取出明文——只用于调试，避免进日志、截图、聊天。
- 备份 `vault.bin` 时必须同时安全保管 `master.pass`，否则无法恢复。
- 本项目不做：企业 SSO、设备信任、浏览器 autofill、审计合规套件；自用开发向。

## 公开仓库提醒

源码仓库可以是 public；**永远不要**把真实 `token`、`master.pass`、明文密钥提交或写进 Issue/PR。
