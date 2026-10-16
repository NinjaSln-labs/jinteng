// Package crypto 提供凭据加密原语：Argon2id 派生 KEK（口令 ‖ 机器指纹），
// AES-256-GCM 密封凭据值。错误信息不包含任何密钥、口令或明文内容。
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id 参数是产品裁定值，逐字使用，勿改。
const (
	argonTime      = 3
	argonMemoryKiB = 64 * 1024 // 单位 KiB
	argonThreads   = 4
)

const (
	// KeyLen 是 DEK/KEK 的字节长度（AES-256）。
	KeyLen = 32
	// SaltLen 是口令派生所需 salt 的字节长度（由调用方提供随机值）。
	SaltLen = 16

	nonceLen = 12 // AES-GCM 标准 nonce
	tagLen   = 16 // AES-GCM 认证标签
)

// valueMagic 标识 SealValue 信封的格式与版本（Jinteng Credential Value v1），
// 供 OpenValue 在解密前拒绝明显不是本格式的 blob。
// 信封布局 magic(4) | nonce(12) | ciphertext，不含 salt；
// 带口令派生的 salt 属于 SealDeviceKey 的信封。
var valueMagic = [4]byte{'J', 'C', 'V', '1'}

// DeriveKEK 用 Argon2id 把 passphrase ‖ fingerprint 作为 password 输入、
// 调用方提供的 16 B salt 派生 32 B KEK。指纹为空或 salt 长度不符一律 error。
func DeriveKEK(passphrase string, fingerprint []byte, salt []byte) ([]byte, error) {
	if len(fingerprint) == 0 {
		return nil, errors.New("crypto: fingerprint 为空")
	}
	if len(salt) != SaltLen {
		return nil, errors.New("crypto: salt 必须为 16 字节")
	}
	password := make([]byte, 0, len(passphrase)+len(fingerprint))
	password = append(password, passphrase...)
	password = append(password, fingerprint...)
	return argon2.IDKey(password, salt, argonTime, argonMemoryKiB, argonThreads, KeyLen), nil
}

// NewDEK 生成 32 字节随机数据密钥。
func NewDEK() ([]byte, error) {
	dek := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, errors.New("crypto: 随机数读取失败")
	}
	return dek, nil
}

// SealValue 用 key（通常为 DEK）直接加密凭据值，返回
// magic(4) | nonce(12) | ciphertext+tag。不带 salt，不带口令派生。
func SealValue(key, plain []byte) ([]byte, error) {
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("crypto: 随机数读取失败")
	}
	blob := make([]byte, 0, len(valueMagic)+nonceLen+len(plain)+tagLen)
	blob = append(blob, valueMagic[:]...)
	blob = append(blob, nonce...)
	return gcm.Seal(blob, nonce, plain, nil), nil
}

// OpenValue 解开 SealValue 产生的信封；任何校验失败只返回不含敏感内容的 error。
func OpenValue(key, blob []byte) ([]byte, error) {
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < len(valueMagic)+nonceLen+tagLen {
		return nil, errors.New("crypto: blob 被截断")
	}
	if !bytes.Equal(blob[:len(valueMagic)], valueMagic[:]) {
		return nil, errors.New("crypto: blob magic 不匹配")
	}
	nonce := blob[len(valueMagic):][:nonceLen]
	ciphertext := blob[len(valueMagic)+nonceLen:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("crypto: 解密失败")
	}
	return plain, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, errors.New("crypto: key 必须为 32 字节")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("crypto: AES 初始化失败")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("crypto: GCM 初始化失败")
	}
	return gcm, nil
}
