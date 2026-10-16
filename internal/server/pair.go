package server

// 配对码：服务端侧签发、单次使用、短 TTL、高熵。库里只存
// 「HMAC(library.key, 码)」这把索引与加密后的载荷——码明文永不落盘，
// 因此搬到异机的服务端材料里既找不到可用码，也造不出索引。
// 码只授登记资格：登记产物只有公钥，新端在下一次 Put 之前取不到任何 DEK。

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
	"github.com/NinjaSln-labs/jinteng/internal/store"
)

// DefaultPairTTL 是配对码的默认存活时限（10 分钟）。
const DefaultPairTTL = 10 * time.Minute

// IssuePairCode 生成一枚 128 bit 一次性配对码，把记录落 pairing 桶，并把码
// 打印到 out（服务端终端，由人工抄到新端）。返回的码只在内存里存在。
func IssuePairCode(st *store.Store, libKey []byte, ttl time.Duration, out io.Writer) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("server: 配对码 TTL 必须为正（得 %s）", ttl)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("server: 配对码随机数读取失败")
	}
	code := hex.EncodeToString(raw)
	if err := storePairCode(st, libKey, code, time.Now().Add(ttl)); err != nil {
		return "", err
	}
	// 唯一一次上屏：人工抄到新端。库里只留 HMAC 索引与加密载荷，码明文不落盘。
	fmt.Fprintf(out, "配对码（一次性，%s 内有效）：%s\n", ttl, code)
	return code, nil
}

// storePairCode 落盘一枚码的记录；IssuePairCode 与测试（可注入过期时间）共用。
func storePairCode(st *store.Store, libKey []byte, code string, expiresAt time.Time) error {
	index, err := crypto.PairIndex(libKey, []byte(code))
	if err != nil {
		return fmt.Errorf("server: 配对码索引派生失败")
	}
	sub, err := crypto.PairKey(libKey)
	if err != nil {
		return fmt.Errorf("server: 配对子密钥派生失败")
	}
	payload, err := json.Marshal(map[string]any{"expires_at": expiresAt.Unix()})
	if err != nil {
		return fmt.Errorf("server: 配对记录序列化失败")
	}
	rec, err := crypto.SealValue(sub, payload)
	if err != nil {
		return fmt.Errorf("server: 配对记录封装失败")
	}
	return st.PutPairing(index, store.Pairing{ExpiresAt: expiresAt.Unix(), Record: rec})
}

// enrollWithCode 把一次登记交给 store.Enroll：配对码判定＋消费、顶替闸、写设备记录
// 全在同一条写事务里（bbolt 单写者串行化并发登记）。返回的 sentinel 由 handler 映射
// 成可区分的错误码；失败时整笔回滚，码不被烧掉。
func (s *Server) enrollWithCode(code, id string, dhPub, sigPub []byte) error {
	if code == "" {
		return fmt.Errorf("%w: 配对码", store.ErrNotFound)
	}
	index, err := crypto.PairIndex(s.libKey, []byte(code))
	if err != nil {
		return err
	}
	return s.st.Enroll(index, id, dhPub, sigPub)
}

// ListPairCodes 输出未消费配对码的索引前缀与剩余时限（绝不打印码明文）。
func ListPairCodes(st *store.Store, libKey []byte, out io.Writer) error {
	codes, err := st.ListPairings()
	if err != nil {
		return err
	}
	if len(codes) == 0 {
		fmt.Fprintln(out, "jinteng pair: 当前没有未使用的配对码")
		return nil
	}
	for _, c := range codes {
		if c.Consumed {
			continue
		}
		remaining := time.Until(time.Unix(c.ExpiresAt, 0)).Round(time.Second)
		fmt.Fprintf(out, "配对码 %s… 剩余 %s（码明文不落盘、不再显示）\n", c.Index[:8], remaining)
	}
	return nil
}

// handleControl 是 serve 终端的本机管理通道：一行一条命令，直到输入结束（EOF）。
//
//	pair                签发一枚一次性配对码并打印（唯一一次上屏）
//	pair list           列出未消费码的索引前缀与剩余时限（绝不打码明文）
//	pair revoke <前缀>  作废一枚未消费码（前缀须唯一命中）
//	revoke <device_id>  撤销一台端（服务端操作员面，见撤销发起面约束）
//
// 这条通道不做网络监听、也不需要账号——它是「人在服务端终端前」的形态本身。
func (s *Server) handleControl(in io.Reader) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			continue
		case line == "pair":
			if _, err := IssuePairCode(s.st, s.libKey, DefaultPairTTL, s.opts.Out); err != nil {
				fmt.Fprintln(s.opts.Out, "jinteng pair new:", err)
			}
		case line == "pair list":
			if err := ListPairCodes(s.st, s.libKey, s.opts.Out); err != nil {
				fmt.Fprintln(s.opts.Out, "jinteng pair list:", err)
			}
		case strings.HasPrefix(line, "pair revoke "):
			prefix := strings.TrimSpace(strings.TrimPrefix(line, "pair revoke"))
			if err := s.st.RevokePairing(prefix); err != nil {
				fmt.Fprintln(s.opts.Out, "jinteng pair revoke:", err)
				continue
			}
			fmt.Fprintln(s.opts.Out, "jinteng: 配对码已作废")
		case strings.HasPrefix(line, "revoke "):
			id := strings.TrimSpace(strings.TrimPrefix(line, "revoke"))
			if err := s.st.RevokeDevice(id); err != nil {
				fmt.Fprintln(s.opts.Out, "jinteng revoke:", err)
				continue
			}
			fmt.Fprintf(s.opts.Out, "jinteng: 端 %s 已撤销（旧 wrap 永不重包，取用面 403）\n", id)
		default:
			fmt.Fprintln(s.opts.Out, "jinteng 管理命令：pair | pair list | pair revoke <索引前缀> | revoke <device_id>")
		}
	}
}
