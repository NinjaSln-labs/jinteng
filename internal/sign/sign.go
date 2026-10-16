// Package sign 提供 v2 请求签名的单点构造：签名串＝对规范化的请求字节做签，
// 客户端产生签名、服务端验签都调用本包的 Canonical，因此不存在「两端字节
// 算不到一块儿」这条路径。
//
// 签名串覆盖方法、路径、排序后的查询串与请求体四段；设备身份、时间戳、nonce
// 随签名头一同送出（X-Jinteng-Device／X-Jinteng-Ts／X-Jinteng-Nonce）。验签用
// 该端登记过的 sig_pub，时间窗与 nonce 重放由调用方另行判定（CheckWindow 与
// store 的 nonce 去重）——三者合起来才是「持有」而非「声称」的证明。
package sign

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
)

// WindowSeconds 是时间戳允许偏移（|now - ts| ≤ 120 s）。
const WindowSeconds = 120

// Header 是一次请求的签名相关头。Ts 为 unix 秒，Nonce 为 16 B 随机的 b64。
type Header struct {
	Device string
	Ts     int64
	Nonce  string
	Sig    string
}

// Canonical 构造被签名的规范字节：method \n path \n query(排序) \n base64(body)。
// 查询串按 key 排序、同 key 的多值再按值排序，空值与 nil 同形。
func Canonical(method, path string, query url.Values, body []byte) []byte {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte('\n')
	sb.WriteString(path)
	sb.WriteByte('\n')
	sb.WriteString(encodeQuery(query))
	sb.WriteByte('\n')
	sb.WriteString(base64.StdEncoding.EncodeToString(body))
	return []byte(sb.String())
}

func encodeQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// CanonicalWithHeaders 在四段规范串之后接上三个签名头的定长形式
// （device \n ts \n nonce）。v2 要求「头三件都在签名覆盖范围内」——否则截获
// 一条合法签名后只换 nonce 就能在窗口内二次使用，防重放面形同虚设。
// 签名与验签都必须调本函数。
func CanonicalWithHeaders(h Header, method, path string, query url.Values, body []byte) []byte {
	var sb bytes.Buffer
	sb.Write(Canonical(method, path, query, body))
	sb.WriteByte('\n')
	sb.WriteString(h.Device)
	sb.WriteByte('\n')
	sb.WriteString(strconv.FormatInt(h.Ts, 10))
	sb.WriteByte('\n')
	sb.WriteString(h.Nonce)
	return sb.Bytes()
}

// Sign 用签名 seed 对规范字节签名，把 b64 签名写入 h.Sig。
// seed 长度非法只返回 error，错误文本不含密钥内容。
func Sign(seed []byte, h *Header, canonical []byte) error {
	if h == nil {
		return errors.New("sign: 缺少 Header")
	}
	sig, err := crypto.SignWithSeed(seed, canonical)
	if err != nil {
		return err
	}
	h.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify 用该端登记的 sig_pub 验证 h.Sig。坏 b64、坏长度、验不通一律 false。
func Verify(pub []byte, h Header, canonical []byte) bool {
	sig, err := base64.StdEncoding.DecodeString(h.Sig)
	if err != nil {
		return false
	}
	return crypto.VerifySig(pub, canonical, sig)
}

// CheckWindow 判定时间戳是否在允许窗口内（两侧超窗都拒：既防滞后重放也防快钟）。
func CheckWindow(ts int64, now time.Time) bool {
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	return diff <= WindowSeconds
}
