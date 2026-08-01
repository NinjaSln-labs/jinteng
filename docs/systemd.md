# systemd 开机自启（二进制部署）

适合本机 / WSL / 树莓派 / 小主机：装一个二进制 + unit，开机自动 `serve`。

> 若已用 Docker 占用 `8787`，先停掉 Compose，再启本服务。

## 一次性安装

```bash
# 1) 构建并安装二进制（勿依赖 /mnt 路径做开机启动）
git clone https://github.com/NinjaSln-labs/lanvault.git
cd lanvault
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/lanvault ./cmd/lanvault
sudo install -m 755 bin/lanvault /usr/local/bin/lanvault

# 2) 初始化数据目录（若尚未有 vault）
export LANVAULT_DIR="$HOME/.lanvault"
mkdir -p "$LANVAULT_DIR" && chmod 700 "$LANVAULT_DIR"
# 非交互示例：
openssl rand -hex 24 > "$LANVAULT_DIR/master.pass"
chmod 600 "$LANVAULT_DIR/master.pass"
LANVAULT_PASSWORD_FILE="$LANVAULT_DIR/master.pass" lanvault init --dir "$LANVAULT_DIR"

# 3) 安装 unit（按实际用户/路径改 Environment）
sudo install -m 644 deploy/lanvault.service /etc/systemd/system/lanvault.service
# 默认模板使用 root + /root/.lanvault；普通用户请改成：
#   Environment=LANVAULT_DIR=/home/YOU/.lanvault
#   Environment=LANVAULT_PASSWORD_FILE=/home/YOU/.lanvault/master.pass
#   User=YOU

sudo systemctl daemon-reload
sudo systemctl enable --now lanvault
```

仓库内模板：[`deploy/lanvault.service`](../deploy/lanvault.service)。

## 验证

```bash
systemctl status lanvault
curl -sS http://127.0.0.1:8787/healthz
# 浏览器打开对接页（无需 Token）
xdg-open http://127.0.0.1:8787/   # 或手动打开
```

读 Token（勿提交、勿贴到公开处）：

```bash
cat ~/.lanvault/token
# 或 root 安装：
# cat /root/.lanvault/token
```

## 日常运维

```bash
sudo systemctl restart lanvault
sudo systemctl stop lanvault
journalctl -u lanvault -f
```

更新二进制后：

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/lanvault ./cmd/lanvault
sudo install -m 755 bin/lanvault /usr/local/bin/lanvault
sudo systemctl restart lanvault
```

## WSL 注意

- `systemctl enable` 在 **发行版启动** 时拉起服务。
- Windows 开机后若未自动启动该 WSL 发行版，服务不会起来；需要时先打开 Ubuntu/WSL，或自行配置「登录时启动 WSL」。
- 二进制请装到 `/usr/local/bin`，不要把 `ExecStart` 指到可能较晚挂载的 `/mnt/d/...`。

## 备份

至少备份这三样（权限保持 `600`）：

| 文件 | 作用 |
|------|------|
| `vault.bin` | 加密保险箱 |
| `master.pass` | 解锁 vault（仅服务端） |
| `token` | LAN API 鉴权（可 rotate） |

## 对接客户端

见 [lan-client.md](./lan-client.md)。服务起来后也可直接打开 `http://<主机>:8787/`。
