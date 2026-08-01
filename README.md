# lanvault

自用局域网密钥库：磁盘上只有密文，项目 / git / CI / agent **不落明文**。开发时用 `lanvault run` 在进程环境里临时注入。

技术选型：**Go 单二进制、无 CGO** —— 本机、NAS、树莓派、Docker 都能跑同一套。

## 快速开始（本机）

```bash
go build -o bin/lanvault ./cmd/lanvault

# 初始化（交互输入 master password；会生成 API token）
./bin/lanvault init

# 写入密钥（值不回显；也可用 echo -n 'secret' | lanvault set openai/key -）
./bin/lanvault set openai/key
./bin/lanvault set db/url 'postgres://...'

./bin/lanvault list
./bin/lanvault get openai/key   # 仅调试时用；勿管道进日志

# 关键命令：密钥进子进程环境，不进仓库
./bin/lanvault run \
  -e OPENAI_API_KEY=openai/key \
  -e DATABASE_URL=db/url \
  -- your-dev-server
```

默认目录：`~/.lanvault/`（`vault.bin` + `token`）。可用 `LANVAULT_DIR` 覆盖。

## 部署模式

| 场景 | 做法 |
|------|------|
| 只本机 | `serve --listen 127.0.0.1:8787` 或不开 serve，CLI 直读写本地 vault |
| **本机 Docker** | [`docs/docker-local.md`](docs/docker-local.md) · `bash deploy/up.sh` |
| **LAN 对接 / 取密钥** | [`docs/lan-client.md`](docs/lan-client.md) |
| 局域网 NAS / 小主机 | `serve --lan`；客户端设 `LANVAULT_URL` + `LANVAULT_TOKEN` |
| systemd 开机自启 | `deploy/lanvault.service` → `systemctl enable --now lanvault` |
| 多架构发布 | `scripts/build.sh` → `dist/lanvault_linux_arm64` 等 |

### 本机 Docker（推荐）

```bash
bash deploy/up.sh
# 脚本会打印 URL + Token；对接细节见 docs/lan-client.md
```

### 其他机器当客户端

```bash
export LANVAULT_URL=http://192.168.1.10:8787
export LANVAULT_TOKEN='lv_...'   # 来自服务端 /data/token 或 ~/.lanvault/token
lanvault list
lanvault run -e API_KEY=openai/key -- npm start
```

服务起来后浏览器打开 **`http://<主机>:8787/`** 即可看 HTTP 对接说明页（无需 Token）。  
完整步骤也见 **[docs/lan-client.md](docs/lan-client.md)**。

> 信任边界：HTTP + Bearer 适合**可信局域网**。暴露到公网请前面加 HTTPS 反代（Caddy/Nginx）并限制来源 IP。

## 安全约定（对齐你的目标）

1. **不明文存盘**：`vault.bin` = Argon2id + AES-256-GCM。
2. **不进 git**：仓库里只保留映射名（`-e ENV=secretName`），永不提交 `vault.bin` / `token` / 真 `.env`。
3. **不进 CI/agent**：CI 或 agent 包装成 `lanvault run ... -- cmd`；脚本里只出现 **secret 名称**，不出现值。
4. **权限**：目录 `0700`，`vault.bin` / `token` / master 文件 `0600`。

## 环境变量

| 变量 | 含义 |
|------|------|
| `LANVAULT_DIR` | 数据目录 |
| `LANVAULT_PASSWORD` | master password（临时用；生产优先 `_FILE`） |
| `LANVAULT_PASSWORD_FILE` | 从文件读 master password |
| `LANVAULT_URL` | 远程 API；设置后 CLI 走网络 |
| `LANVAULT_TOKEN` | API token |

## HTTP API（serve）

- `GET /healthz`
- `GET /v1/secrets` — 列表（无明文）
- `GET /v1/secrets/{name}` — 取值
- `PUT /v1/secrets/{name}` — `{"value":"...","note":"..."}`
- `DELETE /v1/secrets/{name}`
- `POST /v1/resolve` — `{"refs":["openai/key"]}` → 批量取值（给 `run` 用）

鉴权：`Authorization: Bearer <token>` 或 `X-Lanvault-Token`。

## 与「不做」的边界

不做：浏览器 autofill、家庭共享 UX、企业 SSO/PAM、设备信任。  
只做：加密保险箱 + CLI/LAN API + 运行时注入。
