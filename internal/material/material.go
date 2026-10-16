// Package material 描述本端静息材料布局：目录、设备私钥文件的保存与加载，
// 以及供异机取证口径检测器枚举的内容清单。清单只列密文与结构性文件，
// 绝不包含任何明文值文件。
package material

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
)

// dirEnv 覆盖材料目录（测试与自定义部署用）；缺省为 ~/.jinteng/。
const dirEnv = "JINTENG_DIR"

// 静息材料的规范文件名（相对 Dir()）。后续任务（store/audit/server/client）
// 落盘这三类文件时必须与本清单一致。
const (
	DeviceKeyFile  = "device.key"   // SealDeviceKeys JDK2 信封（加密私钥‖签名 seed）
	ConfigFile     = "config.json"  // 客户端/服务端配置
	EventsFile     = "events.jsonl" // 追加式取用事件
	ServerDBFile   = "jinteng.db"   // bbolt 单文件库（密文与按端 wrap 副本）
	ServerCertFile = "server.crt"   // 自签 TLS 证书（静息材料，异机取证面须可见）
	ServerKeyFile  = "server.key"   // 自签 TLS 私钥（权限 ≤0600）
	LibraryKeyFile = "library.key"  // 服务端库密钥（命名密钥化与配对记录加密）
)

// Dir 返回本端材料目录：JINTENG_DIR 非空则用之，否则 ~/.jinteng/。
func Dir() (string, error) {
	if d := os.Getenv(dirEnv); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("material: 无法解析主目录: %v", err)
	}
	return filepath.Join(home, ".jinteng"), nil
}

// Save 把已封装的设备私钥信封写入 Dir()/device.key。
// perms 必须 ≤0600：传入更宽松的权限位（如 0644、0666）一律拒绝并报错，
// 不静默收紧。目录不存在时以 0700 自建。
func Save(keyFile []byte, perms os.FileMode) error {
	return SaveAs(DeviceKeyFile, keyFile, perms)
}

// SaveAs 按规范文件名 name（相对 Dir()，只允许 basename，防目录逃逸）落盘
// 静息材料，权限裁决与 Save 完全一致（>0600 直接拒绝，不静默收紧）。
// TLS 私钥经此落盘，权限判定保持单点，不再另写一套 chmod。
func SaveAs(name string, data []byte, perms os.FileMode) error {
	if perms&^0600 != 0 {
		return fmt.Errorf("material: 拒绝过宽的文件权限 %o（必须 ≤0600）", perms)
	}
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("material: 非法材料文件名 %q", name)
	}
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("material: 无法创建目录 %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, perms); err != nil {
		return fmt.Errorf("material: 写入材料文件失败: %v", err)
	}
	// WriteFile 受 umask 影响，显式 chmod 保证实际权限位就是请求值
	return os.Chmod(path, perms)
}

// LoadKeys 读取 Dir()/device.key 并用口令 ‖ 机器指纹派生的 KEK 解封，同时返回
// X25519 私钥与 Ed25519 签名 seed。指纹不匹配、口令错误、文件内容被截断或仍是
// JDK1 格式都只返回 error（不含敏感内容）。
func LoadKeys(passphrase string, fingerprint []byte) (dhPriv, sigSeed []byte, err error) {
	dir, err := Dir()
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, DeviceKeyFile))
	if err != nil {
		return nil, nil, errors.New("material: 无法读取设备私钥文件")
	}
	return crypto.OpenDeviceKeys(data, passphrase, fingerprint)
}

// LibraryKey 返回服务端库密钥：读 Dir()/library.key，缺失则以 0600
// 生成并落盘，之后复用同一把。它属服务端静息材料——不进配对通道、不进事件、
// 不进日志；与库文件同时被拷走时名字仍可还原，这条收益边界见 spec 的如实条款。
// ponytail: 首次并发启动（两个 serve 抢同一目录）由 bbolt 的单写者文件锁挡在
// 之外，这里不额外加锁；升级路径是先取锁再生成。
func LibraryKey() ([]byte, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, LibraryKeyFile)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) != crypto.KeyLen {
			return nil, errors.New("material: library.key 长度非法")
		}
		return data, nil
	case !errors.Is(err, fs.ErrNotExist):
		// 只在「确实不存在」时生成。读不动的库密钥（权限、IO 错误）必须报错而不是
		// 另起一把：换掉库密钥会让库里全部盲索引、名字密文与配对索引集体失配，
		// 存量凭据按名不可达，那是数据丢失，不是可自愈的缺件。
		return nil, errors.New("material: library.key 不可读（拒绝生成新钥匙）")
	}
	key := make([]byte, crypto.KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("material: 随机数读取失败")
	}
	if err := SaveAs(LibraryKeyFile, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

// Inventory 返回本端静息材料的内容清单（相对 Dir()／JINTENG_DIR 解析），
// 这是当前声明基线；异机口径的检测器＝先扫整树再与本声明集合取差集
// （旧「唯一枚举入口」措辞已作废）。清单为规范
// 布局的固定枚举，不随目录实际内容变化；各项是否存在由消费方 stat 判断。
func Inventory() ([]string, error) {
	return []string{DeviceKeyFile, ConfigFile, EventsFile, ServerDBFile, ServerCertFile, ServerKeyFile, LibraryKeyFile}, nil
}
