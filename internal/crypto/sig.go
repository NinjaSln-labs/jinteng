package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
)

// Ed25519 签名密钥对：seed 32 B 与 X25519 私钥同封进 JDK2 信封，
// 因此签名能力与解密能力共享同一个失效条件（口令 ‖ 机器指纹）。
// 公钥是登记时上报的公开材料，seed 只在解锁后存在于内存。

// NewSignKey 生成一把每端唯一的 Ed25519 签名密钥，返回公钥（32 B）与 seed（32 B）。
func NewSignKey() (pub, seed []byte, err error) {
	k := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, nil, errors.New("crypto: 随机数读取失败")
	}
	priv := ed25519.NewKeyFromSeed(k)
	return append([]byte(nil), priv.Public().(ed25519.PublicKey)...), k, nil
}

// SignWithSeed 用 seed 对消息签名。seed 长度非法只返回 error，不回显任何密钥内容。
func SignWithSeed(seed, msg []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("crypto: 签名 seed 必须为 32 字节")
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg), nil
}

// VerifySig 用登记时上报的公钥验证签名。
func VerifySig(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
