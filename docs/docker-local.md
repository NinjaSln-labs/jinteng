# 本机 Docker 部署

在本机用 Compose 跑 lanvault 服务；同网段其它设备按 [LAN 对接说明](./lan-client.md) 连接。

相关：[文档索引](./README.md) · [systemd 部署](./systemd.md) · [安全](./security.md)

> 当前正式环境若已用 **systemd**（`lanvault.service`）监听 8787，不要同时再起 Docker，以免端口冲突。

## 前置

- 已安装 Docker + Compose 插件
- 已 clone：`git clone https://github.com/NinjaSln/lanvault.git`

## 一键启动

```bash
cd /mnt/d/ubuntu/lanvault
bash deploy/up.sh
```

脚本会：

1. 若缺少 `deploy/secrets/master.pass`，生成随机 master password（`chmod 600`，**勿提交 git**）
2. `docker compose build && up -d`
3. 等待 `/healthz` 就绪
4. 打印本机 URL、建议的局域网 URL，以及如何读取 Token

手动等价步骤：

```bash
cd deploy
# 首次：写入 master password（自己设一串足够长的随机串）
mkdir -p secrets
openssl rand -hex 24 > secrets/master.pass
chmod 600 secrets/master.pass

docker compose build
docker compose up -d
docker compose exec lanvault cat /data/token
```

首次启动入口会自动 `lanvault init`（数据在 volume `lanvault-data`）。

## 端口与访问

`docker-compose.yml` 默认：

```yaml
ports:
  - "127.0.0.1:8787:8787"   # 仅本机
```

| 访问方 | URL |
|--------|-----|
| 本机 CLI / 浏览器调试 | `http://127.0.0.1:8787` |
| 同 LAN 其它设备 | 把 compose 改为 `"8787:8787"` 或 `"0.0.0.0:8787:8787"`，再用 `http://<本机局域网IP>:8787` |

改完后：

```bash
docker compose -f deploy/docker-compose.yml up -d
```

## 本机客户端对接（容器已起来）

浏览器打开对接说明页：

[http://127.0.0.1:8787/](http://127.0.0.1:8787/)

```bash
export LANVAULT_URL="http://127.0.0.1:8787"
export LANVAULT_TOKEN="$(docker compose -f deploy/docker-compose.yml exec -T lanvault cat /data/token | tr -d '\r')"

# 需要本机有 lanvault 二进制
./bin/lanvault list
./bin/lanvault set openai/key
./bin/lanvault run -e OPENAI_API_KEY=openai/key -- printenv OPENAI_API_KEY
```

LAN 其它机器：把 `LANVAULT_URL` 换成局域网 IP，Token 用同一条（安全渠道拷贝）。详见 [lan-client.md](./lan-client.md)。

## 常用运维

```bash
cd deploy
docker compose logs -f lanvault
docker compose restart lanvault
docker compose down          # 停服务；volume 保留密钥数据
docker compose down -v       # 危险：删掉 vault 数据
```

备份：备份 Docker volume，或：

```bash
docker compose exec lanvault ls -la /data
# vault.bin + token；另单独保管 secrets/master.pass
```

## 文件说明

| 路径 | 作用 |
|------|------|
| `deploy/docker-compose.yml` | 本机 Compose |
| `deploy/Dockerfile` | 多阶段构建 |
| `deploy/entrypoint.sh` | 无 vault 则 init，再 serve |
| `deploy/secrets/master.pass` | 解锁保险箱（勿提交） |
| `deploy/up.sh` | 一键 build/up + 打印对接信息 |
