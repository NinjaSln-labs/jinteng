package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// deviceKeyMagic 标识 SealDeviceKeys 信封的格式与版本（Jinteng Device Key v2）。
// 载荷＝dhPriv(32) ‖ sigSeed(32)：加密私钥与签名私钥同封，因此二者共享同一个
// 失效条件（口令 ‖ 机器指纹）——异机取证口径不会从签名面被绕过。
// 信封布局 magic(4) | salt(16) | nonce(12) | ciphertext+tag：salt 由信封自带，
// KEK = DeriveKEK(passphrase, fingerprint, salt)，因此同一口令在指纹不同
// （换机器）时必然派生出不同 KEK ⇒ 解密失败，而不是解出垃圾。
// v1（JDK1，载荷只有一把加密私钥）在 OpenDeviceKeys 里被显式拒绝，不做兼容读。
var deviceKeyMagic = [4]byte{'J', 'D', 'K', '2'}

// deviceKeysLen 是 JDK2 信封的载荷字节数（两把 32 B 私钥材料）。
const deviceKeysLen = 2 * KeyLen

// NewDevice 生成一把每端唯一的 X25519 设备密钥对；pub、priv 均为 32 字节。
func NewDevice() (pub, priv []byte, err error) {
	priv = make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, errors.New("crypto: 随机数读取失败")
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, errors.New("crypto: 设备密钥对生成失败")
	}
	return pub, priv, nil
}

// SealDeviceKeys 用 Argon2id(口令 ‖ 机器指纹) 派生的 KEK 封装两把设备私钥
// （X25519 私钥 32 B ‖ Ed25519 seed 32 B＝64 B）。
// 每次封装随机生成 salt 与 nonce 并置于信封自身（见 deviceKeyMagic 注释布局）。
// fingerprint 由调用方传入（生产路径为 fp.Get()）；fp 层只保证「异机不可复现」，
// 不构成硬件绑定。错误文本不含口令、指纹、私钥或明文内容。
func SealDeviceKeys(dhPriv, sigSeed []byte, passphrase string, fingerprint []byte) ([]byte, error) {
	if len(dhPriv) != KeyLen || len(sigSeed) != KeyLen {
		return nil, errors.New("crypto: 设备私钥材料必须各为 32 字节")
	}
	payload := make([]byte, 0, deviceKeysLen)
	payload = append(payload, dhPriv...)
	payload = append(payload, sigSeed...)
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, errors.New("crypto: 随机数读取失败")
	}
	kek, err := DeriveKEK(passphrase, fingerprint, salt)
	if err != nil {
		return nil, err
	}
	gcm, err := newAESGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("crypto: 随机数读取失败")
	}
	blob := make([]byte, 0, len(deviceKeyMagic)+SaltLen+nonceLen+len(payload)+tagLen)
	blob = append(blob, deviceKeyMagic[:]...)
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	return gcm.Seal(blob, nonce, payload, nil), nil
}

// OpenDeviceKeys 解开 SealDeviceKeys 信封，同时返回两把私钥。指纹不匹配、
// 口令错误、blob 被截断或仍是 v1（JDK1）格式都返回 error；失败不返回任何明文。
// 截断与坏 magic 在派生 KEK 前即拒绝——旧格式绝不静默降级为「能解密不能签名」。
func OpenDeviceKeys(blob []byte, passphrase string, fingerprint []byte) (dhPriv, sigSeed []byte, err error) {
	const overhead = len(deviceKeyMagic) + SaltLen + nonceLen + tagLen
	if len(blob) < overhead {
		return nil, nil, errors.New("crypto: blob 被截断")
	}
	if !bytes.Equal(blob[:len(deviceKeyMagic)], deviceKeyMagic[:]) {
		return nil, nil, errors.New("crypto: blob magic 不匹配（设备密钥格式非 JDK2，请重新登记）")
	}
	salt := blob[len(deviceKeyMagic):][:SaltLen]
	nonce := blob[len(deviceKeyMagic)+SaltLen:][:nonceLen]
	ciphertext := blob[len(deviceKeyMagic)+SaltLen+nonceLen:]
	// 真实派生：异指纹 ⇒ 异 KEK ⇒ GCM 认证必然失败，只会得到 error
	kek, err := DeriveKEK(passphrase, fingerprint, salt)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := newAESGCM(kek)
	if err != nil {
		return nil, nil, err
	}
	payload, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, errors.New("crypto: 解密失败（口令或机器指纹不匹配）")
	}
	if len(payload) != deviceKeysLen {
		return nil, nil, errors.New("crypto: 信封载荷长度非法")
	}
	return payload[:KeyLen], payload[KeyLen:], nil
}
