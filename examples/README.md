# 示例

## `run-dev.sh`

用 `lanvault run` 注入环境变量后执行任意命令，避免把密钥写进 `.env`：

```bash
# 先确保已 set 对应条目：openai/key、db/url
./examples/run-dev.sh npm run dev
./examples/run-dev.sh python app.py
```

需要本机配置好 `LANVAULT_URL` + Token（远程），或可解锁的本地 vault。详见 [docs/lan-client.md](../docs/lan-client.md)。
