package crypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// wrapMagic 标识 WrapDEK 信封的格式与版本（Jinteng DEK Wrap v1）。
// wrap 布局 magic(4) | ephPub(32) | nonce(12) | ciphertext+tag。
var wrapMagic = [4]byte{'J', 'D', 'W', '1'}

// wrapKeyInfo 是 HKDF 的域分隔串；ephemeral 公钥同时充当 HKDF salt，
// 使 wrap 与信封内字段绑定。
const wrapKeyInfo = "jinteng-dek-wrap-v1"

// WrapDEK 把 DEK 封装到某台设备公钥 devPub 之下：X25519 + HKDF-SHA256 +
// AES-256-GCM 的标准组合（HPKE 式单回合，不自定信封算法）。
//
// ephemeral 密钥对由本函数内部每次新生成（裁定）：调用方不持有、也无法复用
// 临时私钥，信封内 ephPub(32) 字段即该临时公钥。
func WrapDEK(dek, devPub []byte) ([]byte, error) {
	if len(dek) != KeyLen {
		return nil, errors.New("crypto: DEK 必须为 32 字节")
	}
	if len(devPub) != curve25519.ScalarSize {
		return nil, errors.New("crypto: 设备公钥必须为 32 字节")
	}
	if isAllZero(devPub) {
		return nil, errors.New("crypto: 设备公钥无效")
	}
	ephPub, ephPriv, err := NewDevice()
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(ephPriv, devPub)
	if err != nil {
		return nil, errors.New("crypto: ECDH 失败")
	}
	if isAllZero(shared) {
		return nil, errors.New("crypto: ECDH 输出无效")
	}
	key, err := hkdf.Key(sha256.New, shared, ephPub, wrapKeyInfo, KeyLen)
	if err != nil {
		return nil, errors.New("crypto: HKDF 失败")
	}
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("crypto: 随机数读取失败")
	}
	blob := make([]byte, 0, len(wrapMagic)+len(ephPub)+nonceLen+len(dek)+tagLen)
	blob = append(blob, wrapMagic[:]...)
	blob = append(blob, ephPub...)
	blob = append(blob, nonce...)
	return gcm.Seal(blob, nonce, dek, nil), nil
}

// UnwrapDEK 用本端设备私钥 devPriv 解出 wrap。ephemeral 公钥一律从信封读取并
// 作为 HKDF salt（裁定：不作参数，故不存在「调用方传错 ephPub」这条路径）。
// 非本端私钥、信封被篡改或截断都只返回 error，不返回明文。
func UnwrapDEK(wrapped, devPriv []byte) ([]byte, error) {
	const overhead = len(wrapMagic) + curve25519.ScalarSize + nonceLen + tagLen
	if len(wrapped) < overhead {
		return nil, errors.New("crypto: wrap 被截断")
	}
	if !bytes.Equal(wrapped[:len(wrapMagic)], wrapMagic[:]) {
		return nil, errors.New("crypto: wrap magic 不匹配")
	}
	envEph := wrapped[len(wrapMagic):][:curve25519.ScalarSize]
	if isAllZero(envEph) {
		return nil, errors.New("crypto: 临时公钥无效")
	}
	shared, err := curve25519.X25519(devPriv, envEph)
	if err != nil {
		return nil, errors.New("crypto: ECDH 失败")
	}
	if isAllZero(shared) {
		return nil, errors.New("crypto: ECDH 输出无效")
	}
	key, err := hkdf.Key(sha256.New, shared, envEph, wrapKeyInfo, KeyLen)
	if err != nil {
		return nil, errors.New("crypto: HKDF 失败")
	}
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := wrapped[len(wrapMagic)+curve25519.ScalarSize:][:nonceLen]
	ciphertext := wrapped[len(wrapMagic)+curve25519.ScalarSize+nonceLen:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("crypto: wrap 解密失败（非本端私钥或数据被篡改）")
	}
	return plain, nil
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}
