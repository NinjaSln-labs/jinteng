package client

// 解锁输入面：机器指纹读取与口令读取。口令来源优先级 TTY > JINTENG_PASSFILE >
// JINTENG_PASSENV。口令、指纹、私钥一律不进 error 文本、不进日志。

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/NinjaSln-labs/jinteng/internal/fp"
)

// currentFingerprint 返回本机 32 字节机器指纹；取不到即 error，绝不降级。
// 指纹绑定的是「整份材料搬到别的机器」这条路，不构成硬件绑定）。
func currentFingerprint() ([]byte, error) {
	return fp.Get()
}

// readPassphrase 按 TTY > JINTENG_PASSFILE > JINTENG_PASSENV 取口令。
//   - TTY：stdin 是字符终端时，用 x/term 静默读取（不回显、不进任何输出流）。
//   - JINTENG_PASSFILE：指向的文件权限必须 ≤0600，否则直接拒绝并说明权限位——
//     这是异机口径的实质防线之一，不做静默收紧。
//   - JINTENG_PASSENV：显式命名的环境变量，其值即口令（自动化用）。
//
// 三个来源都取不到口令时返回错误。返回的 error 文本不含口令内容。
func readPassphrase() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "jinteng 口令: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", errors.New("client: 读取口令失败")
		}
		return string(b), nil
	}
	if pf := os.Getenv("JINTENG_PASSFILE"); pf != "" {
		st, err := os.Stat(pf)
		if err != nil {
			return "", errors.New("client: 无法读取 JINTENG_PASSFILE")
		}
		if st.Mode().Perm()&^0600 != 0 {
			return "", fmt.Errorf("client: 拒绝 JINTENG_PASSFILE 权限 0%o（必须 ≤0600）", st.Mode().Perm())
		}
		data, err := os.ReadFile(pf)
		if err != nil {
			return "", errors.New("client: 无法读取 JINTENG_PASSFILE")
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	if pe := os.Getenv("JINTENG_PASSENV"); pe != "" {
		return pe, nil
	}
	return "", errors.New("client: 未提供口令（TTY／JINTENG_PASSFILE／JINTENG_PASSENV 均不可用）")
}
