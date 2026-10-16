// jinteng 是本端 CLI：init / serve / put / get / run / devices revoke。
//
// 退出码约定（e2e 演练脚本直接引用）：
//
//	0  成功；run 全链路成功时＝子进程退出码（被信号杀死＝128+signal）
//	1  操作失败（网络／解锁／服务端其它拒绝；audit-failed 会随错误文本
//	   如实提示「操作可能已生效，只是事件未能记录」，绝不报成回滚）
//	2  用法错误（参数不合法——发生在任何解锁与联网之前）
//	3  凭据名不存在（client.ErrNotFound）
//	4  未授权设备（client.ErrUnauthDevice）
//	5  设备已撤销（client.ErrRevoked）
//	6  该端无此名的 wrap 副本（client.ErrWrapMissing）
//	7  服务端不可达（client.ErrUnreachable）——本产品不提供缓存值
//
// 注意：run 的 3-6 只可能来自客户端侧（取用失败即不启动子进程）；
// 子进程自己的非零退出码只在 0 之外原样透传，脚本若需区分，让被调用
// 命令使用 ≥10 的退出码。
//
// 任何错误输出不含凭据值／口令／DEK／私钥内容。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/client"
	"github.com/NinjaSln-labs/jinteng/internal/material"
	"github.com/NinjaSln-labs/jinteng/internal/server"
	"github.com/NinjaSln-labs/jinteng/internal/store"
	"github.com/NinjaSln-labs/jinteng/internal/usage"
)

func main() {
	os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr))
}

const usageText = `用法: jinteng <命令> [参数]
命令:
  init   -pair <配对码> -pin <指纹> [-url https://host:8787] [-device <id>]  建立本端材料并向服务端登记
  serve  [-listen 127.0.0.1:8787]                                  启动 TLS 服务（首次生成证书并打印指纹）
  put    <name> <value>                                            写入／覆盖一条凭据
  get    <name>                                                    取用并输出明文
  run    -e <变量名>=<凭据名> [-e ...] <命令> [args...]              注入 env 后执行子进程
  devices revoke <本端 id>                                         撤销本端（取用面即时封锁;撤他端走 serve 终端）
  pair new [-ttl 10m]                                              签发一次性配对码（打印到本终端，人工抄到新端）
  pair list                                                        列出未使用配对码的索引前缀与剩余时限
  pair revoke <索引前缀>                                           作废一枚配对码
  （serve 终端管理通道：pair | pair list | pair revoke <前缀> | revoke <device_id>）
  usage  [-window-days 30] [-out <路径>]                            多端使用统计读数（读本机事件，不出网）`

// cli 是可测试入口：不读全局 os.Args／不 os.Exit，stdout／stderr 注入。
func cli(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "put":
		return cmdPut(args[1:], stdout, stderr)
	case "get":
		return cmdGet(args[1:], stdout, stderr)
	case "run":
		return cmdRun(args[1:], stdout, stderr)
	case "devices":
		return cmdDevices(args[1:], stdout, stderr)
	case "pair":
		return cmdPair(args[1:], stdout, stderr)
	case "usage":
		return cmdUsage(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, usageText)
		return 2
	}
}

// exitOf 把 client 的可区分哨兵映射为约定退出码。
func exitOf(err error) int {
	switch {
	case errors.Is(err, client.ErrNotFound):
		return 3
	case errors.Is(err, client.ErrUnauthDevice):
		return 4
	case errors.Is(err, client.ErrRevoked):
		return 5
	case errors.Is(err, client.ErrWrapMissing):
		return 6
	case errors.Is(err, client.ErrUnreachable):
		return 7
	default:
		return 1
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "%s\n\n（jinteng %s 参数见上）\n", usageText, name)
	}
	return fs
}

func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("init", stderr)
	url := fs.String("url", "https://127.0.0.1:8787", "服务端 HTTPS 地址")
	pin := fs.String("pin", "", "服务端 TLS 证书 SHA-256 指纹（serve 首次生成时打印）")
	dev := fs.String("device", "", "设备 id（缺省自动生成）")
	pair := fs.String("pair", "", "一次性配对码（服务端 jinteng pair new 签发；缺失在任何出网之前被拒）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := client.Init(*url, *pin, *dev, *pair); err != nil {
		fmt.Fprintln(stderr, "jinteng init:", err)
		return 1
	}
	fmt.Fprintln(stdout, "jinteng: 本端材料已建立并向服务端登记")
	return 0
}

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	listen := fs.String("listen", "", "监听地址（缺省 127.0.0.1:8787；跨机时显式写出本机可路由地址，非回环⇒一律走 v2 签名面）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir, err := material.Dir()
	if err != nil {
		fmt.Fprintln(stderr, "jinteng serve:", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintln(stderr, "jinteng serve: 无法创建材料目录")
		return 1
	}
	p, err := server.DBPath()
	if err != nil {
		fmt.Fprintln(stderr, "jinteng serve:", err)
		return 1
	}
	st, err := store.Open(p)
	if err != nil {
		fmt.Fprintln(stderr, "jinteng serve: 打开服务端库失败")
		return 1
	}
	defer st.Close()
	libKey, err := material.LibraryKey()
	if err != nil {
		fmt.Fprintln(stderr, "jinteng serve: 服务端库密钥不可用")
		return 1
	}
	srv := server.New(st, libKey, server.Options{Listen: *listen, Out: stdout, In: os.Stdin})
	if *listen == "" {
		*listen = "127.0.0.1:8787" // 与 server 缺省一致，仅用于提示行
	}
	fmt.Fprintln(stderr, "jinteng serve: 正在监听", *listen)
	if err := srv.Listen(); err != nil {
		fmt.Fprintln(stderr, "jinteng serve: 服务退出:", err)
		return 1
	}
	return 0
}

func openSession(stderr io.Writer) (*client.Session, int) {
	sess, err := client.Unlock()
	if err != nil {
		fmt.Fprintln(stderr, "jinteng: 解锁失败:", err)
		return nil, exitOf(err)
	}
	return sess, 0
}

func cmdPut(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("put", stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "用法: jinteng put <name> <value>")
		return 2
	}
	sess, code := openSession(stderr)
	if sess == nil {
		return code
	}
	defer sess.Close()
	if err := sess.Put(fs.Arg(0), fs.Arg(1)); err != nil {
		fmt.Fprintln(stderr, "jinteng put:", err)
		return exitOf(err)
	}
	return 0
}

func cmdGet(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("get", stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "用法: jinteng get <name>")
		return 2
	}
	sess, code := openSession(stderr)
	if sess == nil {
		return code
	}
	defer sess.Close()
	v, err := sess.Take(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "jinteng get:", err)
		return exitOf(err)
	}
	stdout.Write(v)
	fmt.Fprintln(stdout)
	return 0
}

// envFlags 收集重复的 -e 映射。
type envFlags struct{ m map[string]string }

func (e *envFlags) String() string { return "" }

func (e *envFlags) Set(kv string) error {
	k, v, ok := strings.Cut(kv, "=")
	if !ok || k == "" || v == "" {
		return errors.New("映射须为变量名=凭据名")
	}
	e.m[k] = v
	return nil
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("run", stderr)
	mapping := &envFlags{m: map[string]string{}}
	fs.Var(mapping, "e", "注入映射变量名=凭据名（可重复，至少一个）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// usage 错误必须早于任何解锁与联网（main_test 契约）。
	if len(mapping.m) == 0 || fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	sess, code := openSession(stderr)
	if sess == nil {
		return code
	}
	defer sess.Close()
	exit, err := sess.Run(mapping.m, fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "jinteng run:", err)
		return exitOf(err)
	}
	return exit
}

func cmdDevices(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "revoke" {
		fmt.Fprintln(stderr, "用法: jinteng devices revoke <device_id>")
		return 2
	}
	sess, code := openSession(stderr)
	if sess == nil {
		return code
	}
	defer sess.Close()
	if err := sess.Revoke(args[1]); err != nil {
		fmt.Fprintln(stderr, "jinteng devices revoke:", err)
		return exitOf(err)
	}
	fmt.Fprintln(stdout, "jinteng: 设备已撤销")
	return 0
}

// cmdPair 是服务端本机管理面：签发／列出／作废一次性配对码。
// 码只打印一次、不落盘；库内只有 HMAC 索引与加密载荷。
func cmdPair(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "用法: jinteng pair new|list|revoke [参数]")
		return 2
	}
	p, err := server.DBPath()
	if err != nil {
		fmt.Fprintln(stderr, "jinteng pair:", err)
		return 1
	}
	st, err := store.TryOpen(p, time.Second)
	if err != nil {
		// bbolt 单写者：服务端在跑时这条命令抢不到写锁。配对码的签发因此
		// 走 serve 终端的管理通道（一行「pair」），不在这里跟服务抢锁。
		fmt.Fprintln(stderr, "jinteng pair: 服务端库被占用（serve 正在运行）。请在 serve 终端输入 pair 回车签发，pair list／pair revoke <索引前缀> 同处操作。")
		return 1
	}
	defer st.Close()
	libKey, err := material.LibraryKey()
	if err != nil {
		fmt.Fprintln(stderr, "jinteng pair: 服务端库密钥不可用")
		return 1
	}
	switch args[0] {
	case "new":
		fs := newFlagSet("pair new", stderr)
		ttl := fs.Duration("ttl", server.DefaultPairTTL, "配对码存活时限（默认 10m）")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if _, err := server.IssuePairCode(st, libKey, *ttl, stdout); err != nil {
			fmt.Fprintln(stderr, "jinteng pair new:", err)
			return 1
		} // 码只打印到本终端一次，之后库里只余索引
		return 0
	case "list":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "用法: jinteng pair list")
			return 2
		}
		if err := server.ListPairCodes(st, libKey, stdout); err != nil {
			fmt.Fprintln(stderr, "jinteng pair list:", err)
			return 1
		}
		return 0
	case "revoke":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "用法: jinteng pair revoke <索引前缀>")
			return 2
		}
		if err := st.RevokePairing(args[1]); err != nil {
			fmt.Fprintln(stderr, "jinteng pair revoke:", err)
			return 1
		}
		fmt.Fprintln(stdout, "jinteng: 配对码已作废")
		return 0
	default:
		fmt.Fprintln(stderr, "用法: jinteng pair new|list|revoke [参数]")
		return 2
	}
}

// cmdUsage 输出多端使用统计的可复现读数：读本机 events.jsonl 聚合,
// 不出网、不读凭据内容。-out 把同一份 JSON 落进证据件（0600）。
func cmdUsage(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("usage", stderr)
	window := fs.Int("window-days", usage.WindowDays, "窗口达标判定的窗口天数")
	out := fs.String("out", "", "读数 JSON 的落盘路径（证据件用；0600）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	dir, err := material.Dir()
	if err != nil {
		fmt.Fprintln(stderr, "jinteng usage:", err)
		return 1
	}
	f, err := os.Open(filepath.Join(dir, material.EventsFile))
	if err != nil {
		// 还没有任何事件：这本身就是「样本为 0」的如实读数，不是错误。
		fmt.Fprintln(stderr, "jinteng usage: 事件文件尚不存在，按零样本输出")
	} else {
		defer f.Close()
	}
	var src io.Reader
	if f != nil {
		src = f
	} else {
		src = strings.NewReader("")
	}
	rep, err := usage.Aggregate(src, time.Now(), *window)
	if err != nil {
		fmt.Fprintln(stderr, "jinteng usage: 读数聚合失败")
		return 1
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "jinteng usage: 读数序列化失败")
		return 1
	}
	data = append(data, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, data, 0600); err != nil {
			fmt.Fprintln(stderr, "jinteng usage: 读数落盘失败")
			return 1
		}
	}
	stdout.Write(data)
	return 0
}
