# lanvault

自用局域网密钥库：磁盘上只有密文，项目 / git / CI / agent **不落明文**。开发时用 `lanvault run` 在进程环境里临时注入。

- 仓库：https://github.com/NinjaSln-labs/lanvault
- 技术：**Go 单二进制、无 CGO**（本机 / NAS / 树莓派 / Docker / systemd）
- 服务起来后浏览器打开 **`http://<主机>:8787/`** 即可看对接说明（无需 Token）

## 文档

| 文档 | 说明 |
|------|------|
| [docs/lan-client.md](docs/lan-client.md) | LAN 对接：如何拿 URL / Token、CLI / curl / `run` |
| [docs/systemd.md](docs/systemd.md) | **推荐生产**：二进制 + systemd 开机自启 |
| [docs/docker-local.md](docs/docker-local.md) | 本机 Docker Compose |
| [docs/cli.md](docs/cli.md) | CLI 全命令参考 |
| [docs/security.md](docs/security.md) | 安全模型与约定 |
| [docs/README.md](docs/README.md) | 文档索引 |

## 快速开始（本机 CLI）

```bash
git clone https://github.com/NinjaSln-labs/lanvault.git
cd lanvault
CGO_ENABLED=0 go build -o bin/lanvault ./cmd/lanvault

./bin/lanvault init                 # 创建 vault + API token
./bin/lanvault set openai/key       # 交互输入；或 stdin: echo -n '…' | ./bin/lanvault set openai/key -
./bin/lanvault list

# 关键：只把密钥注入子进程环境，不写进项目目录
./bin/lanvault run \
  -e OPENAI_API_KEY=openai/key \
  -e DATABASE_URL=db/url \
  -- your-dev-server
```

默认数据目录：`~/.lanvault/`（`vault.bin` + `token`）。可用 `LANVAULT_DIR` 覆盖。

## 部署怎么选

| 场景 | 做法 |
|------|------|
| 本机/WSL 长期跑、开机自启 | [docs/systemd.md](docs/systemd.md) |
| 本机 Docker | [docs/docker-local.md](docs/docker-local.md) · `bash deploy/up.sh` |
| 只本机、不常驻 HTTP | CLI 直读写本地 vault，不必 `serve` |
| LAN 其它设备取密钥 | [docs/lan-client.md](docs/lan-client.md) |
| 多架构二进制 | `bash scripts/build.sh` → `dist/` |

**不要**同时让 systemd 与 Docker 都监听 `8787`。

### 最小 LAN 客户端

```bash
export LANVAULT_URL=http://192.168.1.10:8787
export LANVAULT_TOKEN="$(cat /path/to/token)"   # 来自服务端 token 文件
lanvault list
lanvault run -e API_KEY=openai/key -- npm start
```

> 信任边界：HTTP + Bearer 适合**可信局域网**。公网请加 VPN 或 HTTPS 反代并限制来源 IP。详见 [docs/security.md](docs/security.md)。

## 环境变量

| 变量 | 含义 |
|------|------|
| `LANVAULT_DIR` | 数据目录（默认 `~/.lanvault`） |
| `LANVAULT_PASSWORD` | master password（临时；生产优先 `_FILE`） |
| `LANVAULT_PASSWORD_FILE` | 从文件读 master password |
| `LANVAULT_URL` | 远程 API；设置后 CLI 走网络 |
| `LANVAULT_TOKEN` | API token（未设时尝试读 `$LANVAULT_DIR/token`） |

## HTTP API（`serve`）

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/` 或 `/docs` | 否 | HTML 对接说明 |
| GET | `/healthz` | 否 | 探活 |
| GET | `/v1/secrets` | 是 | 列表（无明文） |
| GET | `/v1/secrets/{name}` | 是 | 取值 |
| PUT | `/v1/secrets/{name}` | 是 | `{"value","note"}` |
| DELETE | `/v1/secrets/{name}` | 是 | 删除 |
| POST | `/v1/resolve` | 是 | `{"refs":[…]}` 批量取值 |

鉴权：`Authorization: Bearer <token>` 或 `X-Lanvault-Token`。

## 开发与验证

```bash
CGO_ENABLED=0 go test ./...
bash scripts/smoke.sh          # 需先 build 出 bin/lanvault
```

## 边界（刻意不做）

不做：浏览器 autofill、家庭共享 UX、企业 SSO/PAM、设备信任。  
只做：加密保险箱 + CLI / LAN API + 运行时注入。

## License

[MIT](LICENSE) © 2026 NinjaSln
