# LAN 内对接说明（如何拿到密钥）

相关文档：[systemd 部署](./systemd.md) · [Docker](./docker-local.md) · [CLI](./cli.md) · [安全](./security.md)

**浏览器打开服务根路径即可看对接页（无需 Token）：**

`http://<主机IP>:8787/` 或 `http://<主机IP>:8787/docs`

页面会按你访问的 Host 填好 `LANVAULT_URL` 示例；**不会显示 Token**（仍从服务端 `token` 文件读取）。

---

服务端在局域网提供 HTTP API 后，客户端只用两样东西对接：

| 配置 | 含义 | 从哪来 |
|------|------|--------|
| `LANVAULT_URL` | 服务地址 | `http://<主机局域网IP>:8787` |
| `LANVAULT_TOKEN` | API Token | 服务端数据目录里的 `token` 文件 |

**不要**把 master password 发给客户端；客户端只拿 Token。

---

## 1. 在服务端拿到 URL 和 Token

### Docker（本机 compose）部署时

```bash
# 本机局域网 IP（示例）
hostname -I | awk '{print $1}'

# 读出 Token（首次 up 后）
docker compose -f deploy/docker-compose.yml exec lanvault cat /data/token
```

- URL 示例：`http://192.168.1.23:8787`（把 IP 换成你的）
- 本机容器互访也可用：`http://127.0.0.1:8787`

### systemd / 二进制 `serve` 时

```bash
# Token 默认在（普通用户安装）
cat ~/.lanvault/token
# root + 仓库默认 unit：
# cat /root/.lanvault/token
# 或自定义目录
cat "$LANVAULT_DIR/token"
```

完整开机自启步骤见 [systemd.md](./systemd.md)。

健康检查（无需 Token）：

```bash
curl -sS "http://192.168.1.23:8787/healthz"
# {"status":"ok"}
```

---

## 2. 客户端最小配置

在开发机 shell（或 `~/.bashrc` 私有片段，勿提交仓库）：

```bash
export LANVAULT_URL="http://192.168.1.23:8787"
export LANVAULT_TOKEN="lv_xxxxxxxx"   # 来自服务端 token 文件
```

也可把 Token 落到本地文件（权限 `600`）：

```bash
mkdir -p ~/.lanvault
chmod 700 ~/.lanvault
# 从服务端安全拷贝 token 内容
printf '%s\n' 'lv_xxxxxxxx' > ~/.lanvault/token
chmod 600 ~/.lanvault/token
export LANVAULT_URL="http://192.168.1.23:8787"
# 未设 LANVAULT_TOKEN 时，CLI 会读 ~/.lanvault/token
```

客户端需要本机有 `lanvault` 二进制（从本仓库 `bin/` 或 `scripts/build.sh` 产物拷贝即可），**不需要** master password。

---

## 3. 推荐用法：运行时注入（不进 git / CI / agent）

仓库里只写**密钥名**，不写值：

```bash
lanvault run \
  -e OPENAI_API_KEY=openai/key \
  -e DATABASE_URL=db/url \
  -- npm run dev
```

流程：CLI → `POST /v1/resolve` → 把值放进**子进程环境变量** → 命令退出后本机项目目录仍无明文文件。

Agent / CI 同样包一层：

```bash
lanvault run -e API_KEY=openai/key -- python agent.py
```

---

## 4. 其它获取方式

### CLI

```bash
lanvault list                          # 名称列表（无明文）
lanvault get openai/key                # 调试用；勿打进日志
echo -n 'secret' | lanvault set openai/key -
```

### curl / HTTP

```bash
BASE="http://192.168.1.23:8787"
TOK="$LANVAULT_TOKEN"

# 列表（无 value）
curl -sS -H "Authorization: Bearer $TOK" "$BASE/v1/secrets"

# 取单个
curl -sS -H "Authorization: Bearer $TOK" "$BASE/v1/secrets/openai%2Fkey"

# 批量解析（给脚本注入用）
curl -sS -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"refs":["openai/key","db/url"]}' \
  "$BASE/v1/resolve"

# 写入
curl -sS -X PUT -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"value":"...","note":"dev"}' \
  "$BASE/v1/secrets/openai%2Fkey"
```

也可用头：`X-Lanvault-Token: <token>`。

### 任意语言

对 `POST /v1/resolve` 发 `{"refs":["name1","name2"]}`，用返回的 `values` 填环境变量再 `exec` 你的程序即可。鉴权头同上。

---

## 5. 安全边界（自用 LAN）

- 默认 HTTP + Bearer，只应在**可信局域网**使用。
- 不要把 `8787` 映射到公网；需要远程时加 VPN 或 HTTPS 反代并限制来源 IP。
- Token 等同大门钥匙：泄露后在服务端执行 `lanvault token rotate`（本地模式）并更新各客户端。
- 项目仓库继续 gitignore：`.env`、`vault.bin`、`token`、`master.pass`。
