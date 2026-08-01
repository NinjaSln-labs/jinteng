package server

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	base := publicBaseURL(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(renderDocsHTML(base)))
}

func publicBaseURL(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = "127.0.0.1:8787"
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + host
}

func renderDocsHTML(base string) string {
	b := html.EscapeString(base)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lanvault · LAN 对接说明</title>
<style>
  :root {
    --bg: #0f1216;
    --panel: #171b21;
    --text: #e8eaed;
    --muted: #9aa3ad;
    --line: #2a313a;
    --accent: #6cb6ff;
    --code: #1c222b;
    --warn: #e6b84d;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    color: var(--text);
    background: var(--bg);
  }
  main {
    max-width: 820px;
    margin: 0 auto;
    padding: 32px 20px 64px;
  }
  h1 { font-size: 1.6rem; margin: 0 0 8px; font-weight: 650; }
  h2 {
    font-size: 1.05rem;
    margin: 28px 0 10px;
    padding-top: 8px;
    border-top: 1px solid var(--line);
    font-weight: 600;
  }
  p, li { color: var(--muted); }
  p.lead { color: var(--text); margin: 0 0 16px; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .card {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 14px 16px;
    margin: 12px 0;
  }
  .row { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: baseline; }
  .k { color: var(--muted); min-width: 8rem; }
  .v { color: var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
  code, pre {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.86rem;
  }
  pre {
    background: var(--code);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 12px 14px;
    overflow-x: auto;
    color: var(--text);
    margin: 8px 0 0;
  }
  .warn {
    border-left: 3px solid var(--warn);
    padding: 10px 12px;
    background: #1a1810;
    color: #d8c89a;
    margin: 16px 0;
  }
  .pill {
    display: inline-block;
    border: 1px solid var(--line);
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 12px;
    color: var(--muted);
  }
  table { width: 100%%; border-collapse: collapse; margin-top: 8px; }
  th, td {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--line);
    vertical-align: top;
  }
  th { color: var(--muted); font-weight: 500; font-size: 0.85rem; }
  td { color: var(--text); }
  footer { margin-top: 36px; color: var(--muted); font-size: 0.85rem; }
</style>
</head>
<body>
<main>
  <p class="pill">无需登录 · 本页不含 Token / 密钥明文</p>
  <h1>lanvault 对接说明</h1>
  <p class="lead">局域网加密密钥库。客户端用 URL + API Token 对接；项目 / git / CI / agent 里只写密钥名，用 <code>lanvault run</code> 在运行时注入。</p>

  <div class="card">
    <div class="row"><span class="k">当前服务地址</span><span class="v" id="base">%s</span></div>
    <div class="row"><span class="k">健康检查</span><span class="v"><a href="%s/healthz">%s/healthz</a></span></div>
    <div class="row"><span class="k">本说明</span><span class="v">%s/ 或 %s/docs</span></div>
  </div>

  <div class="warn">
    <strong>Token 不会显示在本页。</strong>
    在服务端读取：Docker 用
    <code>docker compose -f deploy/docker-compose.yml exec lanvault cat /data/token</code>；
    二进制部署用 <code>cat ~/.lanvault/token</code>（或 <code>$LANVAULT_DIR/token</code>）。
  </div>

  <h2>1. 客户端环境变量</h2>
  <pre id="envblock">export LANVAULT_URL='%s'
export LANVAULT_TOKEN='&lt;从服务端 token 文件粘贴&gt;'

# 校验
curl -sS "$LANVAULT_URL/healthz"
lanvault list</pre>

  <h2>2. 推荐：运行时注入（不明文进仓库）</h2>
  <pre>lanvault run \
  -e OPENAI_API_KEY=openai/key \
  -e DATABASE_URL=db/url \
  -- your-dev-server</pre>
  <p>流程：CLI 调用 <code>POST /v1/resolve</code> → 值只进入子进程环境变量 → 磁盘项目目录不落明文。</p>

  <h2>3. HTTP API</h2>
  <table>
    <thead><tr><th>方法</th><th>路径</th><th>说明</th></tr></thead>
    <tbody>
      <tr><td>GET</td><td><code>/healthz</code></td><td>探活，无需 Token</td></tr>
      <tr><td>GET</td><td><code>/v1/secrets</code></td><td>列出名称（无明文）</td></tr>
      <tr><td>GET</td><td><code>/v1/secrets/{name}</code></td><td>取单个值</td></tr>
      <tr><td>PUT</td><td><code>/v1/secrets/{name}</code></td><td>写入 <code>{"value","note"}</code></td></tr>
      <tr><td>DELETE</td><td><code>/v1/secrets/{name}</code></td><td>删除</td></tr>
      <tr><td>POST</td><td><code>/v1/resolve</code></td><td>批量解析 <code>{"refs":["a","b"]}</code></td></tr>
    </tbody>
  </table>
  <p>鉴权头：<code>Authorization: Bearer &lt;token&gt;</code> 或 <code>X-Lanvault-Token: &lt;token&gt;</code></p>

  <h2>4. curl 示例</h2>
  <pre>BASE='%s'
TOK="$LANVAULT_TOKEN"

curl -sS -H "Authorization: Bearer $TOK" "$BASE/v1/secrets"

curl -sS -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"refs":["openai/key"]}' \
  "$BASE/v1/resolve"

curl -sS -X PUT -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"value":"...","note":"dev"}' \
  "$BASE/v1/secrets/openai%%2Fkey"</pre>

  <h2>5. 安全注意</h2>
  <ul>
    <li>本服务默认 HTTP + Bearer，只适合可信局域网。</li>
    <li>不要把端口暴露到公网；远程请用 VPN 或 HTTPS 反代。</li>
    <li>Token 泄露后在服务端 rotate，并更新各客户端。</li>
    <li>切勿把 <code>token</code>、<code>vault.bin</code>、真实 <code>.env</code> 提交进 git。</li>
  </ul>

  <footer>
    lanvault · 打开本页即对接说明书 ·
    <a href="/healthz">/healthz</a>
  </footer>
</main>
</body>
</html>`, b, b, b, b, b, b, b)
}
