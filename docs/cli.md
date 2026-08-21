# CLI 参考

```text
jinteng <command> [flags]
```

全局相关环境变量见 [README](../README.md#环境变量)。  
设了 `JINTENG_URL` 后，读写走远程 API（需 Token）；未设置则直接解锁本地 `vault.bin`。

## 命令

### `init`

创建新保险箱与 API Token。

```bash
jinteng init [--dir PATH]
```

- 交互输入 master password（两次确认）
- 或 `JINTENG_PASSWORD` / `JINTENG_PASSWORD_FILE`
- 非 TTY 且未设密码时会生成随机 master password（打印到 stderr，务必保存）
- 产出：`$JINTENG_DIR/vault.bin`、`$JINTENG_DIR/token`

### `set`

写入或更新一条密钥。

```bash
jinteng set <name> [--note TEXT] [value|-]
```

- 无 `value`：隐藏输入
- `-`：从 stdin 读（适合管道，避免进 shell history）
- `name` 建议用路径风格：`openai/key`、`db/url`

### `get`

打印密钥值（调试用；勿打进日志/聊天）。

```bash
jinteng get <name>
```

### `list` / `ls`

列出名称（与可选 note），**不含明文**。

```bash
jinteng list
```

### `delete` / `rm`

```bash
jinteng delete <name>
```

### `run`

解析密钥并注入子进程环境变量后执行命令——**推荐日常用法**。

```bash
jinteng run -e ENV_NAME=secretName [-e ...] -- <command...>
```

示例：

```bash
jinteng run \
  -e OPENAI_API_KEY=openai/key \
  -e DATABASE_URL=db/url \
  -- npm run dev
```

项目仓库只提交脚本里的 **secret 名称**，不提交值。

### `serve`

启动 HTTP API + 对接说明页。

```bash
jinteng serve [--listen HOST:PORT] [--lan] [--dir PATH]
```

| 旗标 | 含义 |
|------|------|
| `--listen` | 默认 `127.0.0.1:8787` |
| `--lan` | 等价 `--listen 0.0.0.0:8787` |
| `--dir` | vault 目录 |

需能解锁 vault：`JINTENG_PASSWORD` 或 `JINTENG_PASSWORD_FILE`。

公开页面（无 Token）：`GET /`、`GET /docs`  
探活：`GET /healthz`

### `token`

```bash
jinteng token show      # 显示本地 token 文件
jinteng token rotate    # 轮换（须本地模式；更新服务端后再发各客户端）
```

### `version` / `help`

```bash
jinteng version
jinteng help
```

## 退出码

- `0` 成功
- `1` 业务/IO 错误
- `2` 用法错误
