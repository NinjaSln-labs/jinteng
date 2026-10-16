package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// 服务端库密钥（library.key）的一钥两用：靠域分隔串把
// 「凭据名查找索引」与「名字密文／配对记录加密」分开，两者互不稀释。
const (
	nameEncInfo  = "jinteng-name-enc-v1"
	pairEncInfo  = "jinteng-pair-v1"
	pairIndexTag = "pair-idx"
)

// SubKey 从 library.key（32 B）派生指定用途的 32 B 子密钥。
// info 为空或 base 长度非法都返回 error，错误文本不含密钥内容。
func SubKey(base []byte, info string) ([]byte, error) {
	if len(base) != KeyLen {
		return nil, errors.New("crypto: library.key 必须为 32 字节")
	}
	if info == "" {
		return nil, errors.New("crypto: 缺少域分隔串")
	}
	key, err := hkdf.Key(sha256.New, base, nil, info, KeyLen)
	if err != nil {
		return nil, errors.New("crypto: 子密钥派生失败")
	}
	return key, nil
}

// NameIndex 由 library.key 对凭据名做 HMAC-SHA256，返回 hex 查找索引。
// 它同时是库内查找键与事件里的 name_blind_index（取代早先的无密钥 HKDF，
// 命名密钥化这条）。
func NameIndex(key, name []byte) (string, error) {
	if len(key) != KeyLen {
		return "", errors.New("crypto: library.key 必须为 32 字节")
	}
	if len(name) == 0 {
		return "", errors.New("crypto: 凭据名不能为空")
	}
	m := hmac.New(sha256.New, key)
	m.Write(name)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// SealName／OpenName：真名以 library.key 派生的名字子密钥加解密（AES-256-GCM 信封）。
func SealName(key, name []byte) ([]byte, error) {
	sub, err := SubKey(key, nameEncInfo)
	if err != nil {
		return nil, err
	}
	return SealValue(sub, name)
}

func OpenName(key, blob []byte) ([]byte, error) {
	sub, err := SubKey(key, nameEncInfo)
	if err != nil {
		return nil, err
	}
	return OpenValue(sub, blob)
}

// PairIndex 是配对码在库内的查找键：HMAC(library.key, "pair-idx" ‖ code)。
// 库里因此既不存码明文、也不存可离线还原的构造。
func PairIndex(key, code []byte) (string, error) {
	if len(code) == 0 {
		return "", errors.New("crypto: 配对码不能为空")
	}
	return NameIndex(key, append([]byte(pairIndexTag), code...))
}

// PairKey 是配对记录载荷的加密子密钥（配 SealValue／OpenValue 使用）。
func PairKey(key []byte) ([]byte, error) {
	return SubKey(key, pairEncInfo)
}
