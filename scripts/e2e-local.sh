#!/usr/bin/env bash
# scripts/e2e-local.sh — 金縢本端端到端演练
#
# 一条命令跑完真实旅程并自带断言：
#   pair new（serve 前离线签发一次性配对码）→ serve（随机回环口，首启打印
#   TLS 指纹）→ init -pair（吃真指纹面：不设
#   JINTENG_FP_OVERRIDE_DIR，由 fp.Get() 读本机 /etc/machine-id）→ put×2 →
#   get（输出与合成值逐字节比对，比对在内存）→ run -e（子进程断言注入值
#   正确、且继承 env 里没有任何 JINTENG_ 前缀控制面变量）→ devices revoke →
#   再 get（必须拿退出码 5）。
# 收尾把「服务端全部可见面」（jinteng.db＋events.jsonl＋config.json＋
# server.crt/server.key）用 strings＋grep -a 两路扫描，断言不含任何本次
# 合成凭据值或口令；事件计数按 action+outcome 过滤，与脚本逐条核实的实际
# 成功次数相等。
#
# 红线：凭据值／口令／DEK／私钥不出现在脚本任何输出里——需要留痕处只落
#   sha256 摘要前缀；合成值只存活在本进程内存与临时目录（退出即删）。
# 隔离：JINTENG_DIR 用临时目录，绝不碰真实 ~/.jinteng/（脚本结束做存在性
#   回执）；服务只绑 127.0.0.1；收尾 kill 服务并以 /proc 复查无残留进程。
# 前置条件：脚本开头 command -v 断言全部外部依赖工具；扫描器的三种结局
#   （命中／无命中／没跑成）在代码里分开处理，"没跑成"一律红，绝不并入
#   "命中 0"。换一台缺 binutils/procps 的机器会直接失败而不是谎报绿。
#
# 已知天花板（与 judge3 同口径）：put/run 的合成值短暂出现在本进程 argv
# （同权限读者可见 /proc/<pid>/cmdline），度量对象是落盘面，不是进程表。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO="${GO:-/usr/local/go/bin/go}"

note() { printf '[e2e] %s\n' "$*"; }
fail() { printf 'E2E FAIL: %s\n' "$*" >&2; exit 1; }

# ---- 依赖前置断言 ----
# 缺任一外部工具都必须红：否则 strings／pgrep 缺席时扫描会静默空转，脚本仍
# 能一路 GREEN 并谎称「两路命中 0」——本脚本交付的是验收证据面。
DEPS=(python3 strings pgrep sed grep head tail cut tr od sha256sum
      mktemp seq sleep rm chmod mkdir)
for tool in "${DEPS[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    fail "缺少依赖工具：$tool（断言面不完整，拒绝以空转冒充通过）"
  fi
done
if ! command -v "$GO" >/dev/null 2>&1; then
  fail "缺少 Go：$GO（可用 GO=<path> 覆盖）"
fi
note "依赖工具前置断言：${#DEPS[@]} 个外部命令＋Go 全部就位"

# 16 字节随机值的 sha256 摘要前缀——脚本输出里唯一允许的“值相关”留痕。
digest() { printf '%s' "$1" | sha256sum | cut -c1-16; }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# ---- 临时工作区与合成值（值只在内存／临时目录，退出即删） ----
WORK="$(mktemp -d "${TMPDIR:-/tmp}/jinteng-e2e-XXXXXX")"
chmod 700 "$WORK"
MATS="$WORK/mats"
BIN="$WORK/bin/jinteng"
mkdir -p "$MATS" "$WORK/bin"

# 真实 ~/.jinteng 回执：跑前不存在 ⇒ 跑后也必须不存在（隔离红线）。
HOME_JINTENG_BEFORE=0
if [ -e "$HOME/.jinteng" ]; then HOME_JINTENG_BEFORE=1; fi

# ---- 收尾：kill 服务、/proc 复查、删除临时目录（任何退出路径都执行） ----
SERVE_PID=""
cleanup() {
  local rc=$?
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$SERVE_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -9 "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
    if [ -e "/proc/$SERVE_PID" ]; then
      printf 'E2E FAIL: serve pid=%s 在 /proc 仍可见（残留进程）\n' "$SERVE_PID" >&2
      rc=1
    else
      note "残留复查：serve pid=$SERVE_PID 已从 /proc 消失"
    fi
  fi
  local leftover prc=0
  leftover="$(pgrep -f "$WORK/bin/jinteng" 2>/dev/null)" || prc=$?
  # pgrep 约定：0=找到进程，1=一个都不匹配，>=2=扫描本身失败。
  # 只有 1 才能宣称"进程数=0"；>=2 必须红，否则残留复查等于没做。
  if [ "$prc" -gt 1 ]; then
    printf 'E2E FAIL: pgrep 残留复查未能执行（rc=%s），进程数未知\n' "$prc" >&2
    rc=1
  elif [ -n "$leftover" ]; then
    printf 'E2E FAIL: 仍有 jinteng 进程存活：%s\n' "$leftover" >&2
    rc=1
  else
    note "残留复查：pgrep 本工作区二进制进程数=0（rc=1 确认无匹配）"
  fi
  if [ "$HOME_JINTENG_BEFORE" -eq 0 ] && [ -e "$HOME/.jinteng" ]; then
    printf 'E2E FAIL: 真实 ~/.jinteng 被本次运行创建（隔离被破坏）\n' >&2
    rc=1
  fi
  rm -rf "$WORK"
  if [ "$rc" -eq 0 ]; then
    note "GREEN：临时目录已删除，旅程全部断言通过"
  fi
  exit "$rc"
}
trap cleanup EXIT

# ---- 真指纹面：绝不设测试钩子 ----
unset JINTENG_FP_OVERRIDE_DIR
export JINTENG_DIR="$MATS"
export JINTENG_PASSENV="pw-$(rand_hex 16)"
VAL_A="e2e-val-A-$(rand_hex 16)"
VAL_B="e2e-val-B-$(rand_hex 16)"
DEVICE="dev-e2e-$(rand_hex 4)"
[ -r /etc/machine-id ] || fail "环境不满足：/etc/machine-id 不可读，真指纹面无法演练"
note "fp_source=real:/etc/machine-id（本机值不落输出；machine-id 前 8 位=$(head -c 8 /etc/machine-id)）"
note "合成值摘要（只落摘要）：pass=$(digest "$JINTENG_PASSENV") valA=$(digest "$VAL_A") valB=$(digest "$VAL_B") device=$DEVICE"

# ---- 构建真实二进制（无 CGO，零新增依赖） ----
( cd "$ROOT" && CGO_ENABLED=0 "$GO" build -o "$BIN" ./cmd/jinteng ) || fail "构建 jinteng 失败"

# ---- 配对码：在 serve 抢走库写锁之前离线签发（bbolt 单写者） ----
PAIR_RAW="$("$BIN" pair new 2>&1)" || fail "pair new 失败：$(printf %s "$PAIR_RAW" | tail -c 200)"
PAIR_CODE="$(printf '%s' "$PAIR_RAW" | awk -F'：' 'NF>1 {gsub(/[[:space:]]/, "", $NF); print $NF; exit}')"
[ "${#PAIR_CODE}" -eq 32 ] || fail "配对码格式非法（须 32 位十六进制，得长度 ${#PAIR_CODE}）"
note "配对码已签发（一次性；码本身不落输出，摘要=$(digest "$PAIR_CODE")）"

# ---- 起服务：只绑 127.0.0.1，随机端口，等首启打印 TLS 指纹 ----
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')" \
  || fail "取回环随机口失败"
# ponytail: 探口与 serve 绑定之间有 TOCTOU 竞态（与 judge3 freePort 同款）；
# 本机同刻无并发抢口，升级路径＝把监听 socket 交给子进程。
"$BIN" serve -listen "127.0.0.1:$PORT" >"$WORK/serve.log" 2>"$WORK/serve.err.log" &
SERVE_PID=$!
note "serve 已启动 pid=$SERVE_PID listen=127.0.0.1:$PORT"

PIN=""
for _ in $(seq 1 300); do
  PIN="$(sed -n 's/.*指纹 (SHA-256): //p' "$WORK/serve.log" | head -1)"
  if [ -n "$PIN" ]; then break; fi
  kill -0 "$SERVE_PID" 2>/dev/null || fail "serve 在打印指纹前退出：$(tail -c 200 "$WORK/serve.err.log")"
  sleep 0.1
done
[ -n "$PIN" ] || fail "等 TLS 指纹超时（30s）"
case "$PIN" in
  *[!0-9a-fA-F]* | '') fail "指纹格式非法（须 64 hex）" ;;
esac
[ "${#PIN}" -eq 64 ] || fail "指纹长度=${#PIN}（须 64 hex）"
note "serve 首启打印指纹（哈希，非私钥）：${PIN:0:16}…"

# ---- CLI 调用器：核实退出码，输出只回传调用方（不上屏） ----
cli() { # $1=期望退出码 $2=标签；其余为 jinteng 参数。输出捕获返回。
  local want="$1" label="$2"; shift 2
  local out rc=0
  out="$("$BIN" "$@" 2>&1)" || rc=$?
  if [ "$rc" -ne "$want" ]; then
    # stderr 摘要只取末尾 200 字节；产品保证 error 文本不含值。
    fail "$label：退出码=$rc 期望=$want；输出摘要=$(printf '%s' "$out" | tail -c 200)"
  fi
  printf '%s' "$out"
}

# 事件计数：JSONL 键按字典序落盘（action 在 outcome 之前），按两字段过滤。
ev_count() { # $1=action $2=outcome
  local n
  n="$(grep -c "\"action\":\"$1\".*\"outcome\":\"$2\"" "$MATS/events.jsonl" 2>/dev/null || true)"
  printf '%s' "${n:-0}"
}
ev_expect() { # $1=action $2=outcome $3=期望计数
  local got
  got="$(ev_count "$1" "$2")"
  [ "$got" = "$3" ] || fail "事件计数 action=$1 outcome=$2：实际=$got 期望=$3"
  note "事件 action=$1 outcome=$2 计数=$got（与实际成功次数逐条相等）"
}

# 实际成功次数由脚本逐条核实的退出码累积，最后与事件账对照。
succ_enroll=0; succ_put=0; succ_getsrv=0; succ_run=0; succ_revoke=0; succ_getdenied=0

# ---- 旅程 ----
cli 0 "init" init -url "https://127.0.0.1:$PORT" -pin "$PIN" -device "$DEVICE" -pair "$PAIR_CODE" >/dev/null
succ_enroll=$((succ_enroll + 1))
note "init 成功（真指纹面材料已建立并向服务端登记）"

cli 0 "put E2E_CRED_A" put E2E_CRED_A "$VAL_A" >/dev/null
succ_put=$((succ_put + 1))
cli 0 "put E2E_CRED_B" put E2E_CRED_B "$VAL_B" >/dev/null
succ_put=$((succ_put + 1))
note "put×2 成功（值只经 argv 进内存，脚本不落盘）"

got="$(cli 0 "get E2E_CRED_A" get E2E_CRED_A)"
succ_getsrv=$((succ_getsrv + 1))
[ "$got" = "$VAL_A" ] || fail "get 输出与合成值 A 不符（摘要=$(digest "$got")）"
note "get 明文已在内存逐字节比对一致（摘要=$(digest "$got")）"

# run：子进程三重断言——注入值正确（对照摘要）、值非空、继承 env 里没有任何
# JINTENG_ 前缀控制面变量（零明文与机器绑定这条的正面证据；被注入命令要再调
# jinteng 必须显式重供控制面 env，本旅程不需要故不再调）。注入值与预期
# 明文的一致性用 sha256 摘要对照，明文本身不进 argv、不落任何文件。
EXP_DIGEST_A="$(digest "$VAL_A")"
child='
  [ -n "${E2E_TOKEN:-}" ] || exit 11
  [ -z "${JINTENG_DIR:-}" ] && [ -z "${JINTENG_PASSENV:-}" ] \
    && [ -z "${JINTENG_PASSFILE:-}" ] && [ -z "${JINTENG_FP_OVERRIDE_DIR:-}" ] || exit 12
  got="$(printf %s "$E2E_TOKEN" | sha256sum | cut -c1-16)"
  [ "$got" = "$1" ] || exit 13
  echo RUN_OK
'
runout="$(cli 0 "run" run -e E2E_TOKEN=E2E_CRED_A sh -c "$child" sh "$EXP_DIGEST_A")"
succ_run=$((succ_run + 1))
succ_getsrv=$((succ_getsrv + 1)) # 一次 run -e ⇒ 服务端一次 get ＋客户端一条 run 事件
printf '%s' "$runout" | grep -q '^RUN_OK$' || fail "run 子进程断言脚本未打印 RUN_OK"
note "run 成功：注入值摘要对照一致，且子进程 env 无任何 JINTENG_ 前缀控制面变量"

cli 0 "devices revoke" devices revoke "$DEVICE" >/dev/null
succ_revoke=$((succ_revoke + 1))
note "devices revoke 成功"

cli 5 "get(撤销后)" get E2E_CRED_A >/dev/null
succ_getdenied=$((succ_getdenied + 1))
note "撤销后 get 如约定拿到退出码 5（ErrRevoked）"

# ---- 事件账：按 action+outcome 过滤，与逐条核实的实际成功次数相等 ----
ev_expect enroll ok "$succ_enroll"
ev_expect put ok "$succ_put"
ev_expect get ok "$succ_getsrv"
ev_expect run ok "$succ_run"
ev_expect revoke ok "$succ_revoke"
ev_expect get denied "$succ_getdenied"

# ---- 服务端可见面零明文断言（只扫“值”，凭据名明文作 key 是既定事实） ----
SURFACE=(jinteng.db events.jsonl config.json server.crt server.key library.key)
# 两路扫描（grep -aF 与 strings→定长字符串）逐文件逐值执行，且严格区分三种
# 结局：命中／无命中／扫描器本身没跑成。第三种必须红——否则在缺 binutils
# 或文件缺席的机器上，"命中 0" 只是空转的假象，而本脚本的产出是验收证据。
SCAN_ROUTES=0
scan_face() { # $1=文件 $2=值 $3=面标签
  local f="$1" v="$2" tag="$3" rc=0 sout name="${1##*/}"
  if [ ! -f "$f" ]; then
    fail "$tag 扫描目标不存在：$name（无文件≠命中 0，旅程未真实触达该面）"
  fi
  grep -aFq -- "$v" "$f" || rc=$?
  if [ "$rc" -eq 0 ]; then
    fail "$tag grep 路命中明文凭据值（摘要=$(digest "$v")，文件=$name）"
  elif [ "$rc" -gt 1 ]; then
    fail "$tag grep 路扫描未执行：rc=$rc 文件=$name（不得当作命中 0）"
  fi
  SCAN_ROUTES=$((SCAN_ROUTES + 1))
  rc=0
  sout="$(strings "$f" 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$tag strings 路扫描未执行：rc=$rc 文件=$name（不得当作命中 0）"
  fi
  # 用 here-string 而非管道：grep -q 提前退出不会给 strings/printf 留 SIGPIPE
  # 让 pipefail 把"命中"误报成"扫描失败"。
  if grep -qF -- "$v" <<<"$sout"; then
    fail "$tag strings 路命中明文凭据值（摘要=$(digest "$v")，文件=$name）"
  fi
  SCAN_ROUTES=$((SCAN_ROUTES + 1))
}
for v in "$VAL_A" "$VAL_B" "$JINTENG_PASSENV"; do
  for f in "${SURFACE[@]}"; do
    scan_face "$MATS/$f" "$v" "可见面"
  done
  # device.key 也在盘上，顺手断言口令同样不在其信封明文里（信封本身是密文）。
  scan_face "$MATS/device.key" "$v" "device.key"
done
note "零明文扫描：${#SURFACE[@]} 件可见面＋device.key × 3 个合成值 × grep -a／strings 两路，实际执行 $SCAN_ROUTES 路（$((${#SURFACE[@]} + 1))×3×2），命中 0"

note "断言全部通过；进入收尾（kill serve → /proc 复查 → 删除临时目录）"
