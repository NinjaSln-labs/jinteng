# 金縢（jinteng）

自用加密密钥库：磁盘上只有密文，项目 / git / CI / agent **不落明文**。开发时用 `jinteng run` 在进程环境里临时注入。

名称取《尚书·金縢》：密辞封入金縢之匮，非事不开。

- 仓库：https://github.com/NinjaSln-labs/jinteng（原 `lanvault`）
- 技术：**Go 单二进制、无 CGO**（常见 Linux 可跑；也可用 Docker / systemd）
- 服务起来后浏览器打开 **`http://<主机>:8787/`** 即可看对接说明（无需 Token）
- 定位：自用 / 小团队密钥库（MVP），不是企业 PAM

## 文档

| 文档 | 说明 |
|------|------|
| [docs/client.md](docs/client.md) | 客户端对接：URL / Token / `run` |
| [docs/systemd.md](docs/systemd.md) | 本机常驻 / 开机自启（推荐长期跑） |
| [docs/docker-local.md](docs/docker-local.md) | 本机 Docker Compose |
| [docs/cli.md](docs/cli.md) | CLI 全命令参考 |
| [docs/security.md](docs/security.md) | 安全模型与约定 |

## 快速开始（本机 CLI）

```bash
git clone https://github.com/NinjaSln-labs/jinteng.git
cd jinteng
CGO_ENABLED=0 go build -o bin/jinteng ./cmd/jinteng

./bin/jinteng init                 # 创建 vault + API token
./bin/jinteng set openai/key       # 交互输入；或 stdin: echo -n '…' | ./bin/jinteng set openai/key -
./bin/jinteng list

# 常用：只把密钥注入子进程环境，不写进项目目录
./bin/jinteng run \
  -e OPENAI_API_KEY=openai/key \
  -e DATABASE_URL=db/url \
  -- your-dev-server
```

默认数据目录：`~/.jinteng/`（`vault.bin` + `token`）。可用 `JINTENG_DIR` 覆盖。

## 部署怎么选

| 场景 | 做法 |
|------|------|
| Linux 本机长期跑（systemd） | [docs/systemd.md](docs/systemd.md) |
| WSL 常驻 | 同上；指 **WSL 发行版启动时**拉起，不等于 Windows 开机即起 |
| 本机 Docker | [docs/docker-local.md](docs/docker-local.md) · `bash deploy/up.sh` |
| NAS / 其它 Linux 盒子 | 用 Docker，或按 systemd 文档自行装二进制（无厂商专用包） |
| 只本机、不常驻 HTTP | CLI 直读写本地 vault，不必 `serve` |
| 远程客户端取密钥 | [docs/client.md](docs/client.md) |
| 多架构二进制 | `bash scripts/build.sh` → `dist/` |

**不要**同时让 systemd 与 Docker 都监听 `8787`。

### 最小远程客户端

```bash
export JINTENG_URL=https://vault.example.com
# 服务端 token：二进制/systemd 多为 ~/.jinteng/token 或 /root/.jinteng/token
# Docker：docker compose exec jinteng cat /data/token
export JINTENG_TOKEN="$(tr -d '\n' < ~/.jinteng/token)"
jinteng list
jinteng run -e API_KEY=openai/key -- npm start
```

> 信任边界：默认 HTTP + Bearer。不要把 `8787` 裸暴露到公网；远程请用 VPN 或 HTTPS 反代。详见 [docs/security.md](docs/security.md)。

## 环境变量

| 变量 | 含义 |
|------|------|
| `JINTENG_DIR` | 数据目录（默认 `~/.jinteng`） |
| `JINTENG_PASSWORD` | master password（临时调试用；常驻服务请用 `_FILE`） |
| `JINTENG_PASSWORD_FILE` | 从文件读 master password |
| `JINTENG_URL` | 远程 API；设置后 CLI 走网络 |
| `JINTENG_TOKEN` | API token（未设时尝试读 `$JINTENG_DIR/token`） |

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

鉴权：`Authorization: Bearer <token>` 或 `X-Jinteng-Token`。

## 开发与验证

```bash
CGO_ENABLED=0 go test ./...
make smoke                     # 本地 CLI + 临时 serve
```

## 从 lanvault 迁移

| 旧 | 新 |
|----|----|
| 二进制 `lanvault` | `jinteng` |
| `LANVAULT_*` | `JINTENG_*` |
| `~/.lanvault` | `~/.jinteng`（可直接挪目录并改名） |
| 头 `X-Lanvault-Token` | `X-Jinteng-Token` |
| Token 前缀 `lv_` | 新发为 `jt_`（旧 token 仍可用到 rotate） |

Vault 文件魔数未改，旧 `vault.bin` 可继续用。

## 边界（刻意不做）

不做：浏览器 autofill、家庭共享 UX、企业 SSO/PAM、设备信任。  
只做：加密保险箱 + CLI / HTTP API + 运行时注入。

## License

[MIT](LICENSE) © 2026 NinjaSln
