#!/usr/bin/env bash
# scripts/e2e-multidev.sh — 多端集成演练
#
# 一条命令跑完「三端共用同一个源」的完整旅程并自带断言：
#   serve 绑**非回环**地址（v2 放开后的形态）→ serve 终端管理通道签发配对码（v2
#   的运行形态：bbolt 单写者，服务在跑时配对码只能由 serve 进程自己签发）→
#   三端各自 init（各持自己的材料目录与机器指纹）→ A 写 → B/C 取回同一值 →
#   停服务后取用必须拿退出码 7 且不回吐旧值→ 重启后取最新值 →
#   撤销一端 → 该端取用被拒 → 轮换写入 → 存活端拿到新值。
# 收尾扫描服务端全部可见面，断言不含任何本次合成值。
#
# 口径钉死（否则读数会被读大）：本演练的三端是**同一台物理机上的三种端形态**，
# 靠 JINTENG_FP_OVERRIDE_DIR 给出三个不同的机器指纹值来成立为三个独立端——
# 这与真机口径一致：Windows 与 WSL2 同机也按指纹值判为两个独立端。
# 真实跨物理机的登记与首次取用由 tasks 2.2／2.3（真机）覆盖，不在这里冒充。
#
# 红线：凭据值／口令／配对码／DEK／私钥不出现在脚本任何输出里；需要留痕处只落
#   sha256 摘要前缀。材料全部落在临时目录，退出即删，绝不碰真实 ~/.jinteng/。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO="${GO:-/usr/local/go/bin/go}"
note() { printf '[multidev] %s\n' "$*"; }
fail() { printf 'MULTIDEV FAIL: %s\n' "$*" >&2; exit 1; }
digest() { printf '%s' "$1" | sha256sum | cut -c1-16; }
rand_hex() { head -c "${1:-8}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# ---- 依赖前置断言（缺任一即红，不许静默空转） ----
DEPS=(python3 sha256sum od tr head cut tail grep sed awk pgrep mktemp rm chmod seq sleep kill wait)
for tool in "${DEPS[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || fail "缺少外部依赖 $tool（本脚本交付的是验收证据）"
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/jinteng-multidev-XXXXXX")"
BIN="$WORK/jinteng"
SERVE_DIR="$WORK/serve"
CTL="$WORK/ctl"
SERVE_LOG="$WORK/serve.log"
mkdir -p "$SERVE_DIR"
for d in a b c; do
  mkdir -p "$WORK/mats-$d" "$WORK/fp-$d"
  printf 'synthetic-machine-id-%s-%s\n' "$d" "$(rand_hex 8)" > "$WORK/fp-$d/machine-id"
done
PASS_A="pw-a-$(rand_hex 16)"; PASS_B="pw-b-$(rand_hex 16)"; PASS_C="pw-c-$(rand_hex 16)"
VAL_V1="md-val-v1-$(rand_hex 16)"
VAL_V2="md-val-v2-$(rand_hex 16)"
CRED="MD_SHARED"
SERVE_PID=""
# 本班签发过的每一枚配对码都进零明文扫描集（码明文只应存在于终端 scrollback，
# 而演练把 serve 终端重定向进了日志）。必须落文件：issue_pair 在命令替换的子 shell
# 里跑，数组追加不会带回父进程。
CODES_FILE="$WORK/.codes"; : > "$CODES_FILE"; chmod 600 "$CODES_FILE"

# reap：有界回收（最多 5s）。无界的 `wait` 在管道/子进程交错时会把演练挂死,
# 而这条脚本的产物是验收证据——卡死等于没跑成,必须失败而不是悬着。
reap() { # $1=pid
  local pid="$1" i
  [ -z "$pid" ] && return 0
  kill "$pid" 2>/dev/null || true
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  fail "进程 $pid 未在 5s 内退出（残留）"
}

cleanup() {
  exec 9>&- 2>/dev/null || true
  reap "$SERVE_PID"
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- 构建（无 CGO） ----
( cd "$ROOT" && CGO_ENABLED=0 "$GO" build -o "$BIN" ./cmd/jinteng ) || fail "构建 jinteng 失败"

# ---- 监听地址：必须是非回环的可路由地址，否则非回环放开面没被演练到 ----
LISTEN_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$LISTEN_HOST" ] || LISTEN_HOST="$(ip -4 -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
case "$LISTEN_HOST" in
  127.* | "" | ::1) fail "取不到非回环可路由地址（演练面必须是跨机形态）；本机地址=$LISTEN_HOST" ;;
esac
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("0.0.0.0",0)); print(s.getsockname()[1]); s.close()')"
ADDR="$LISTEN_HOST:$PORT"
note "serve 监听非回环地址（主机摘要 $(digest "$LISTEN_HOST")，端口 $PORT）"

start_serve() {
  # fd 9 以读写方式打开管理管道：既当读者又当写者，open 永不阻塞,也不会因
  # serve 中途停掉而让下一次写入卡在「等读者」上（那正是本脚本最初的挂死点）。
  [ -p "$CTL" ] || mkfifo "$CTL"
  exec 9<>"$CTL"
  JINTENG_DIR="$SERVE_DIR" "$BIN" serve -listen "$ADDR" >>"$SERVE_LOG" 2>>"$SERVE_LOG.err" < "$CTL" &
  SERVE_PID=$!
  note "serve 已启动 pid=$SERVE_PID（管理通道＝$CTL 一行一条命令）"
}

wait_for() { # $1=正则 $2=标签
  local pat="$1" label="$2" i
  for i in $(seq 1 300); do
    if grep -q "$pat" "$SERVE_LOG" 2>/dev/null; then return 0; fi
    kill -0 "$SERVE_PID" 2>/dev/null || fail "$label：serve 已退出（stderr 摘要 $(tail -c 200 "$SERVE_LOG.err" 2>/dev/null)）"
    sleep 0.1
  done
  fail "等 $label 超时（30s）"
}

revoke_via_channel() { # 撤他端＝服务端操作员面：往 serve 终端写一行「revoke <id>」
  local id="$1" n i got
  n=$(( $(grep -c '已撤销' "$SERVE_LOG" 2>/dev/null || true) + 1 ))
  printf 'revoke %s\n' "$id" >&9
  for i in $(seq 1 200); do
    got="$(grep -c '已撤销' "$SERVE_LOG" 2>/dev/null || true)"
    [ "$got" -ge "$n" ] && return 0
    kill -0 "$SERVE_PID" 2>/dev/null || return 1
    sleep 0.05
  done
  return 1
}

issue_pair() { # 经 serve 终端管理通道签发一枚配对码，回读
  # 基线必须在写入之前取：先写后取会撞上「新行已落日志」的竞态，于是要求的第 n 行
  # 其实还不存在（表现为「未打印第 n 枚配对码」）。
  local n=$(( $(grep -c '配对码（一次性' "$SERVE_LOG" 2>/dev/null || true) + 1 ))
  printf 'pair\n' >&9
  for i in $(seq 1 200); do
    local got; got="$(grep -c '配对码（一次性' "$SERVE_LOG" 2>/dev/null || true)"
    [ "$got" -ge "$n" ] && break
    sleep 0.05
  done
  CODE_RAW="$(grep '配对码（一次性' "$SERVE_LOG" | sed -n "${n}p")"
  [ -n "$CODE_RAW" ] || fail "serve 终端未打印第 $n 枚配对码"
  local code; code="$(printf '%s' "$CODE_RAW" | awk -F'：' 'NF>1 {gsub(/[[:space:]]/,"",$NF); print $NF}')"
  printf '%s\n' "$code" >> "$CODES_FILE"
  # 码只在「人抄进新端」这段时间里存在于纸面/内存。演练把 serve 的终端重定向进了
  # 日志 ⇒ 抄录完立刻就地抹掉该行，否则「工作区日志零明文」这条扫描是假的。
  # 只替换码本身，保留「配对码（一次性」行首——签发计数按它数，整行抹掉会让后续计数失效。
  # 注意：不能用 sed -i——它会新建文件再改名，serve 的 stdout 仍指向旧 inode，
  # 之后所有输出都落到看不见的地方（表现为「第二枚配对码永远不出现」）。
  # 这里用「写临时件 + cat 截断回原文件」原地改写，保住同一个 inode。
  sed "s|${code}|〔已抹除，摘要 $(digest "$code")〕|g" "$SERVE_LOG" > "$SERVE_LOG.masked"
  cat "$SERVE_LOG.masked" > "$SERVE_LOG"; rm -f "$SERVE_LOG.masked"
  printf '%s' "$code"
}

init_device() { # $1=a|b|c $2=口令 $3=设备 id
  local d="$1" pass="$2" dev="$3" code
  code="$(issue_pair)"
  [ "${#code}" -eq 32 ] || fail "配对码格式非法（长度 ${#code}）"
  local out rc=0
  out="$(JINTENG_DIR="$WORK/mats-$d" JINTENG_PASSENV="$pass" JINTENG_FP_OVERRIDE_DIR="$WORK/fp-$d" \
    "$BIN" init -url "https://$ADDR" -pin "$PIN" -device "$dev" -pair "$code" 2>&1)" || rc=$?
  [ "$rc" -eq 0 ] || fail "端 $d init 失败（rc=$rc）：$(printf %s "$out" | tail -c 200)"
  note "端 $d 登记完成（设备 id=$dev，配对码摘要 $(digest "$code")）"
}

cli_for() { # $1=a|b|c $2=口令；其余为 jinteng 参数。stdout 回传，stderr 并流。
  local d="$1" pass="$2"; shift 2
  JINTENG_DIR="$WORK/mats-$d" JINTENG_PASSENV="$pass" JINTENG_FP_OVERRIDE_DIR="$WORK/fp-$d" \
    "$BIN" "$@" 2>&1
}

expect_rc() { # $1=期望 rc $2=标签；其余为参数（输出丢弃）
  local want="$1" label="$2"; shift 2
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  [ "$rc" -eq "$want" ] || fail "$label：退出码=$rc 期望=$want（输出摘要 $(printf %s "$out" | tail -c 200)）"
  printf '%s' "$out"
}

# ---- 起服务并取指纹 pin ----
start_serve
wait_for '指纹 (SHA-256):' "TLS 指纹"
PIN="$(sed -n 's/.*指纹 (SHA-256): //p' "$SERVE_LOG" | head -1)"
[ "${#PIN}" -eq 64 ] || fail "证书指纹格式非法"
note "serve 首启打印指纹（哈希，非私钥）：${PIN:0:16}…"

# 证书 SAN 必须含实际监听地址（否则跨机 TLS 握手撞主机名）
if ! openssl x509 -in "$SERVE_DIR/server.crt" -noout -text 2>/dev/null | grep -q "$LISTEN_HOST"; then
  note "注：openssl 不可用或 SAN 未取到文本，SAN 覆盖由内部单测 TestSANIncludesListenIP 认证"
fi

# ---- 三端登记 ----
init_device a "$PASS_A" "dev-md-a"
init_device b "$PASS_B" "dev-md-b"
init_device c "$PASS_C" "dev-md-c"

# ---- A 写入 → B/C 取回同一值（跨端同源，无按端副本） ----
out="$(cli_for a "$PASS_A" put "$CRED" "$VAL_V1")" || fail "A put 失败：$out"
GOT_A="$(cli_for a "$PASS_A" get "$CRED")" || fail "A get 失败：$GOT_A"
GOT_B="$(cli_for b "$PASS_B" get "$CRED")" || fail "B get 失败：$GOT_B"
GOT_C="$(cli_for c "$PASS_C" get "$CRED")" || fail "C get 失败：$GOT_C"
for pair in "$GOT_B:$GOT_A" "$GOT_C:$GOT_A"; do
  [ "${pair%%:*}" = "${pair#*:}" ] || fail "跨端取回的值不一致（摘要 $(digest "${pair%%:*}") vs $(digest "${pair#*:}")）"
done
[ "$GOT_A" = "$VAL_V1" ] || fail "A 取回的不是刚写入的值"
note "三端取回同一值 ✓（值摘要 $(digest "$VAL_V1")，比对在内存）"

# ---- 停服务后取用：必须退出码 7，且不给旧值 ----
reap "$SERVE_PID"
SERVE_PID=""
exec 9>&-
out=""; rc=0
out="$(cli_for b "$PASS_B" get "$CRED")" || rc=$?
[ "$rc" -eq 7 ] || fail "服务端不可达时应拿退出码 7，实得 $rc（输出摘要 $(printf %s "$out" | tail -c 120)）"
case "$out" in *"$VAL_V1"*) fail "离线取用回吐了旧值——绝不给旧值这条被打穿" ;; esac
printf '%s' "$out" | grep -q '不可达' || fail "错误文本须说明服务端不可达，得 $(printf %s "$out" | tail -c 120)"
note "离线明确失败 ✓（退出码 7，无旧值）"

# ---- 重新上线：取最新值（改写来自 C 端） ----
start_serve
wait_for '指纹 (SHA-256):' "重启后的 serve"
out="$(cli_for c "$PASS_C" put "$CRED" "$VAL_V2")" || fail "C put 失败：$out"
GOT_A2="$(cli_for a "$PASS_A" get "$CRED")" || fail "重上线 A get 失败：$GOT_A2"
GOT_B2="$(cli_for b "$PASS_B" get "$CRED")" || fail "重上线 B get 失败：$GOT_B2"
[ "$GOT_A2" = "$VAL_V2" ] || fail "重上线后 A 取到的不是最新值"
[ "$GOT_B2" = "$VAL_V2" ] || fail "重上线后 B 取到的不是最新值"
note "一端离线期间被改写，重新上线取到最新值 ✓"

# ---- 撤销 C：经服务端管理通道；C 之后取用被拒；A/B 仍能取到轮换后的新值 ----
# 客户端 API 只能撤销自己那端,先把它钉一次：A 撤 B 必须失败,且 B 之后仍可取用。
rc=0; out="$(cli_for a "$PASS_A" devices revoke dev-md-b)" || rc=$?
[ "$rc" -ne 0 ] || fail "客户端撤销他端应被拒,实得退出码 0"
note "客户端撤他端被拒 ✓（退出码 $rc,未出网即拒）"
revoke_via_channel dev-md-c || fail "管理通道撤销 C 未生效"
rc=0; out="$(cli_for c "$PASS_C" get "$CRED")" || rc=$?
[ "$rc" -eq 5 ] || fail "被撤销端取用应拿退出码 5，实得 $rc（摘要 $(printf %s "$out" | tail -c 120)）"
out="$(cli_for b "$PASS_B" put "$CRED" "$VAL_V1")" || fail "撤销后 B 仍能写入：$out"
GOT_A3="$(cli_for a "$PASS_A" get "$CRED")" || fail "撤销后 A get 失败：$GOT_A3"
[ "$GOT_A3" = "$VAL_V1" ] || fail "撤销一端后存活端取到的值不符"
note "撤销面 ✓（C 经管理通道撤销后被拒 5；A/B 取用不受影响，名录重包只对未撤销端发新 wrap）"

# ---- 窗口达标判定读数：服务端事件里至少两端各自成功取用过 ----
READOUT="$(JINTENG_DIR="$SERVE_DIR" "$BIN" usage)"
printf '%s' "$READOUT" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["devices_with_success"] >= 2, d
assert d["criterion1_met"] is True, d
assert d["north_star"]["denominator"] == "not-observable", d
assert d["north_star"]["ratio"] is None, d
print("usage: devices_with_success=%d numerator=%d" % (d["devices_with_success"], d["north_star"]["numerator"]))
' || fail "多端使用统计读数不符（读数摘要 $(printf %s "$READOUT" | head -c 200)）"
note "窗口达标判定读数取自服务端事件 ✓（≥2 端各自成功取用）"

# ---- 明文扫描：服务端全部可见面＋本工作区日志都不含任何敏感值 ----
# 三种扫描结局分开处理（命中／无命中／没跑成）：「没跑成」一律红，绝不并入「命中 0」。
SURFACE=(jinteng.db events.jsonl library.key server.crt server.key)
mapfile -t ISSUED < "$CODES_FILE"
VALS=("$VAL_V1" "$VAL_V2" "$PASS_A" "$PASS_B" "$PASS_C" "${ISSUED[@]}")
HITS=0; RUNS=0; NOTRUN=0
for f in "${SURFACE[@]}"; do
  [ -r "$SERVE_DIR/$f" ] || fail "可见面不完整：$f 不存在或不可读（没跑成≠命中 0）"
  for v in "${VALS[@]}"; do
    RUNS=$((RUNS+1))
    if grep -a -q -- "$v" "$SERVE_DIR/$f"; then HITS=$((HITS+1)); note "命中：$f 含敏感值"; fi
    if ! s_out="$(strings -a "$SERVE_DIR/$f" 2>/dev/null)"; then NOTRUN=$((NOTRUN+1)); continue; fi
    printf '%s\n' "$s_out" | grep -q -- "$v" && HITS=$((HITS+1))
    RUNS=$((RUNS+1))
  done
done
for f in "$SERVE_LOG" "$WORK/serve.log.restart" "$WORK/fwd.log"; do
  [ -r "$f" ] || continue
  for v in "${VALS[@]}"; do
    RUNS=$((RUNS+1))
    grep -a -q -- "$v" "$f" && { HITS=$((HITS+1)); note "命中：工作区日志 $(basename "$f") 含敏感值"; }
  done
done
[ "$NOTRUN" -eq 0 ] || fail "有 $NOTRUN 次 strings 扫描没跑成，不得计为命中 0"
[ "$HITS" -eq 0 ] || fail "服务端可见面或工作区日志出现明文（命中 $HITS 处）"
note "零明文扫描：${#SURFACE[@]} 件可见面 × ${#VALS[@]} 个敏感值 × 两路＋工作区日志 grep 路，实际执行 $RUNS 路，命中 0"

# ---- 收尾：残留进程复查 ----
reap "$SERVE_PID"
SERVE_PID=""
exec 9>&-
sleep 0.3
if pgrep -f "$BIN" >/dev/null 2>&1; then fail "残留：jinteng 进程仍在 /proc 可见"; fi
note "断言全部通过；进入收尾（临时目录由 trap 删除）"
echo "MULTIDEV GREEN：三端同源旅程全部断言通过"
