// Package fp 提供机器指纹：一个跨调用稳定、用于把密钥材料绑定到本端的 32 字节
// 值。指纹只保证「异机不可复现」，不构成硬件绑定。
package fp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// overrideEnv 是测试钩子：设置后从该目录读取 machine-id 等价物，
// 目录为空或文件为空/空白时 Get 必须返回 error，绝不返回空指纹或降级值。
const overrideEnv = "JINTENG_FP_OVERRIDE_DIR"

// Get 返回 32 字节机器指纹（对平台机器标识做 SHA-256）。
// 任何环节取不到有效标识都返回 error，不降级。
func Get() ([]byte, error) {
	id, err := identifier()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(id)
	return sum[:], nil
}

// identifier 返回未哈希的平台机器标识（非空）。
func identifier() ([]byte, error) {
	if dir := os.Getenv(overrideEnv); dir != "" {
		return readIDFile(filepath.Join(dir, "machine-id"))
	}
	switch runtime.GOOS {
	case "windows":
		return windowsMachineGuid()
	case "darwin":
		return darwinIOPlatformUUID()
	default: // linux（WSL2 同路径）
		return readIDFile("/etc/machine-id")
	}
}

func readIDFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fp: 无法读取机器标识 %s: %v", path, err)
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return nil, fmt.Errorf("fp: 机器标识 %s 为空", path)
	}
	return []byte(id), nil
}

// darwinIOPlatformUUID 与 windowsMachineGuid 按计划编写；本机（linux）只实测
// linux 路径。二者通过系统命令读取，取不到非空值一律 error。
func darwinIOPlatformUUID() ([]byte, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return nil, fmt.Errorf("fp: ioreg 调用失败: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		_, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		uuid := strings.Trim(strings.TrimSpace(val), `"`)
		if uuid != "" {
			return []byte(uuid), nil
		}
	}
	return nil, errors.New("fp: 未取到 IOPlatformUUID")
}

func windowsMachineGuid() ([]byte, error) {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err != nil {
		return nil, fmt.Errorf("fp: reg query 调用失败: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || fields[0] != "MachineGuid" {
			continue
		}
		guid := fields[len(fields)-1]
		if guid != "" {
			return []byte(guid), nil
		}
	}
	return nil, errors.New("fp: 未取到 MachineGuid")
}
