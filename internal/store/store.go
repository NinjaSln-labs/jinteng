// Package store 服务端存储：bbolt 单文件库。密文与按端 wrap 副本分桶存放；
// 撤销只置状态位，O(1)，绝不遍历重包其余密文——实质防线是
// 「凭据轮换后旧 wrap 解不出新 DEK」，由 PutSecret 的按名整体替换语义提供地基。
// replay 桶承载 v2 的 nonce 去重，pairing 桶承载一次性配对码记录。
// 错误文本只含 name/id 等定位信息，不含密文、DEK 或任何明文值。
package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
)

var (
	bucketSecrets = []byte("secrets") // key: nameBlindIndex → 密文信封
	bucketNames   = []byte("names")   // key: nameBlindIndex → 真名密文
	bucketDevices = []byte("devices") // key: id              → revoked(1B)|dh_pub(32B)|sig_pub(32B)
	bucketWraps   = []byte("wraps")   // key: index\x00deviceId → 该端 DEK wrap 副本

	// bucketReplay 存 nonce 去重表：key: deviceId\x00nonce → 1B 标记。
	// 落库而不是放进程内存，服务端重启后重放判定仍成立。
	bucketReplay = []byte("replay")

	// bucketPairing 存配对码记录（记录本身由调用方用 library.key 加密后传入，
	// 服务端首次起服时启用）。这里先建桶，避免二次改 Open()。
	bucketPairing = []byte("pairing")

	// keySep 分隔复合键，name 与设备 id 本身禁止包含它。
	keySep = byte(0x00)

	// nonceRetentionPerDevice 是每端 nonce 的保留上界（有界，不无限增长）。
	// ponytail: 超出后删字典序最小者（nonce 为随机 b64，该顺序≈插入顺序之外
	// 的近似）；上限 512/端配合 ±120 s 窗口足够，升级路径是更大窗口或持久 WAL。
	nonceRetentionPerDevice = 512

	// ErrNotFound 表示目标（凭据名或设备 id）不存在。
	ErrNotFound = errors.New("store: 目标不存在")

	// ErrDeviceExists 表示登记目标 id 已在册，且带来的签名公钥与在册的那把不一致。
	// 签名公钥是端的身份锚：换它就不是「同一台端重新登记」，而是顶替。
	ErrDeviceExists = errors.New("store: 设备已在册且签名公钥不符")

	// ErrDeviceRevoked 表示 wraps 里出现了已撤销端（服务端不变量，不靠调用方自觉）。
	ErrDeviceRevoked = errors.New("store: 设备已撤销")

	// ErrPairingConsumed／ErrPairingExpired 是配对码的两种不可用状态，与「码不存在」
	// 一起都归为调用方的 invalid-pair-code，但分开成 sentinel 才能让 IO 类意外不被掩盖。
	ErrPairingConsumed = errors.New("store: 配对码已消费")
	ErrPairingExpired  = errors.New("store: 配对码已过期")
)

// Device 是一条设备注册记录：一把加密公钥与一把签名公钥并存。
// Revoked 是取用面判定的唯一依据；两把公钥都是公开材料，任何模型下都不是秘密。
type Device struct {
	ID      string
	DhPub   []byte
	SigPub  []byte
	Revoked bool
}

// Pairing 是一条一次性配对码记录。Record 是调用方用 library.key
// 派生子密钥加密后的不透明载荷——库里既不存码明文，也不存未加密的过期信息。
type Pairing struct {
	ExpiresAt int64
	Consumed  bool
	Record    []byte
}

// Store 封装一个已打开的 bbolt 库。
type Store struct {
	db *bolt.DB
}

// Open 打开（不存在则创建）path 处的库，并确保全部桶就位。
// 权限 0600：静息材料只允许属主读写。
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("store: 打开数据库失败: %v", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketSecrets, bucketNames, bucketDevices, bucketWraps, bucketReplay, bucketPairing} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("store: 初始化桶失败: %v", err)
	}
	return &Store{db: db}, nil
}

// TryOpen 像 Open，但在别的进程（通常是正在跑的 serve）持有写锁时于 timeout
// 内快速失败，而不是无限悬挂——配对码管理命令用它，好把「请在 serve 终端签发」
// 这条指引如实打印出来而不是卡死。
func TryOpen(path string, timeout time.Duration) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("store: 打开数据库失败: %w", err)
	}
	st := &Store{db: db}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketSecrets, bucketNames, bucketDevices, bucketWraps, bucketReplay, bucketPairing} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("store: 初始化桶失败: %v", err)
	}
	return st, nil
}

// Close 关闭底层库文件。重复调用是 bbolt 的 no-op。
func (s *Store) Close() error {
	return s.db.Close()
}

func wrapKey(name, deviceID string) []byte {
	return append(namePrefix(name), deviceID...)
}

func namePrefix(name string) []byte {
	return append([]byte(name), keySep)
}

// validName 拒绝空 name 与含复合键分隔符的 name。
func validName(name string) error {
	if name == "" {
		return errors.New("store: 凭据名不能为空")
	}
	if bytes.ContainsRune([]byte(name), rune(keySep)) {
		return errors.New("store: 凭据名含非法字符")
	}
	return nil
}

func validDeviceID(id string) error {
	if id == "" {
		return errors.New("store: 设备 id 不能为空")
	}
	if bytes.ContainsRune([]byte(id), rune(keySep)) {
		return errors.New("store: 设备 id 含非法字符")
	}
	return nil
}

// PutSecret 写入盲索引的密文信封、真名密文及该批按端 wrap（key 为设备 id）。
// 覆盖语义（轮换路径的地基）：同一索引再次写入 ⇒ 新密文替换旧密文，
// 并整体替换该索引的全部按端 wrap——入参未列出的旧设备 wrap 一律删除。
// 空索引、含分隔符的索引、空名字密文、空密文、空/非法设备 id、空 wrap 都拒绝。
func (s *Store) PutSecret(index string, nameCipher, ciphertext []byte, wraps map[string][]byte) error {
	if err := validName(index); err != nil {
		return err
	}
	if len(nameCipher) == 0 {
		return errors.New("store: 名字密文不能为空")
	}
	if len(ciphertext) == 0 {
		return errors.New("store: 密文不能为空")
	}
	for id, w := range wraps {
		if err := validDeviceID(id); err != nil {
			return fmt.Errorf("store: wraps[%q]: %w", id, err)
		}
		if len(w) == 0 {
			return fmt.Errorf("store: 设备 %q 的 wrap 为空", id)
		}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		// wraps↔devices 的不变量在同一条写事务里判定：先查后写在并发下会让「取完
		// 名录与落库之间刚被撤销」的端拿到新 DEK 副本，也允许悬空 wrap 落库。
		dev := tx.Bucket(bucketDevices)
		for id := range wraps {
			v := dev.Get([]byte(id))
			if v == nil {
				return fmt.Errorf("%w: 设备 %q", ErrNotFound, id)
			}
			if len(v) != deviceRecordLen {
				return fmt.Errorf("store: 设备 %q 记录长度非法", id)
			}
			if v[0] == 1 {
				return fmt.Errorf("%w: 设备 %q", ErrDeviceRevoked, id)
			}
		}
		if err := tx.Bucket(bucketSecrets).Put([]byte(index), ciphertext); err != nil {
			return err
		}
		if err := tx.Bucket(bucketNames).Put([]byte(index), nameCipher); err != nil {
			return err
		}
		wb := tx.Bucket(bucketWraps)
		prefix := namePrefix(index)
		c := wb.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return err
			}
		}
		for id, w := range wraps {
			if err := wb.Put(wrapKey(index, id), w); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetSecret 返回盲索引的密文信封与该索引当前全部按端 wrap。
// index 不存在返回 ErrNotFound。返回值均为拷贝，事务外有效。
// 错误文本只截索引前缀（它是单向 HMAC，但整串进日志没好处）。
func (s *Store) GetSecret(index string) ([]byte, map[string][]byte, error) {
	if err := validName(index); err != nil {
		return nil, nil, err
	}
	var (
		ct    []byte
		wraps = map[string][]byte{}
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSecrets).Get([]byte(index))
		if v == nil {
			return fmt.Errorf("%w: 凭据索引 %.8s…", ErrNotFound, index)
		}
		ct = append([]byte(nil), v...)
		prefix := namePrefix(index)
		c := tx.Bucket(bucketWraps).Cursor()
		for k, w := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, w = c.Next() {
			id := string(k[len(prefix):])
			wraps[id] = append([]byte(nil), w...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return ct, wraps, nil
}

// DeleteSecret 硬删除一个盲索引：密文、名字密文与该索引下全部按端 wrap
// 在同一条写事务内移除。索引不存在返回 ErrNotFound；非法索引在任何写入前拒绝。
// 不设墓碑：事件日志保留 action=delete 的盲索引审计痕迹，恢复只能重新写入。
func (s *Store) DeleteSecret(index string) error {
	if err := validName(index); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketSecrets).Get([]byte(index)) == nil {
			return fmt.Errorf("%w: 凭据索引 %.8s…", ErrNotFound, index)
		}
		if err := tx.Bucket(bucketSecrets).Delete([]byte(index)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketNames).Delete([]byte(index)); err != nil {
			return err
		}
		wb := tx.Bucket(bucketWraps)
		prefix := namePrefix(index)
		c := wb.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return err
			}
		}
		return nil
	})
}

// encodeDevice 序列化为 revoked(1B)|dh_pub(32B)|sig_pub(32B)＝65 B；
// 与 bucketDevices 注释一致。旧 33 B 记录（只有一把公钥）在 decode 时被拒绝。
func encodeDevice(d Device) ([]byte, error) {
	if len(d.DhPub) != crypto.KeyLen || len(d.SigPub) != crypto.KeyLen {
		return nil, fmt.Errorf("store: 设备 %q 公钥长度必须各为 %d 字节", d.ID, crypto.KeyLen)
	}
	buf := make([]byte, 0, 1+2*crypto.KeyLen)
	if d.Revoked {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, d.DhPub...)
	return append(buf, d.SigPub...), nil
}

func decodeDevice(id string, v []byte) (Device, error) {
	if len(v) != deviceRecordLen {
		return Device{}, fmt.Errorf("store: 设备 %q 记录长度非法（%d 字节，期望 %d；旧格式需重新登记）",
			id, len(v), deviceRecordLen)
	}
	return Device{
		ID:      id,
		DhPub:   append([]byte(nil), v[1:1+crypto.KeyLen]...),
		SigPub:  append([]byte(nil), v[1+crypto.KeyLen:]...),
		Revoked: v[0] == 1,
	}, nil
}

// deviceRecordLen 是设备记录的字节数：状态位 ＋ 两把 32 B 公钥。
const deviceRecordLen = 1 + 2*crypto.KeyLen

// AddDevice 注册设备。id 必须非空且未被占用（重复 id 拒绝，不改写已有记录），
// dhPub 与 sigPub 必须各为 32 字节（登记时上报两把公钥）。
func (s *Store) AddDevice(id string, dhPub, sigPub []byte) error {
	if err := validDeviceID(id); err != nil {
		return err
	}
	rec, err := encodeDevice(Device{ID: id, DhPub: dhPub, SigPub: sigPub})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		if b.Get([]byte(id)) != nil {
			return fmt.Errorf("store: 设备 %q 已存在", id)
		}
		return b.Put([]byte(id), rec)
	})
}

// ListDevices 返回全部在册设备（设备名录）。任一记录长度非法
// （含旧 33 B 格式）即整体报错——不做兼容读，也不静默跳过一条坏记录。
func (s *Store) ListDevices() ([]Device, error) {
	var out []Device
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketDevices).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			d, err := decodeDevice(string(k), v)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Device 读取设备记录；不存在返回 ErrNotFound。
func (s *Store) Device(id string) (Device, error) {
	if err := validDeviceID(id); err != nil {
		return Device{}, err
	}
	var d Device
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketDevices).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: 设备 %q", ErrNotFound, id)
		}
		var err error
		d, err = decodeDevice(id, v)
		return err
	})
	return d, err
}

// RevokeDevice 撤销：只翻转状态位，O(1)，不遍历、不重包任何 wrap/密文。
// 对不存在 id 返回 error；重复撤销幂等。取用面如何拒绝由服务层）判定。
func (s *Store) RevokeDevice(id string) error {
	if err := validDeviceID(id); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: 设备 %q", ErrNotFound, id)
		}
		if len(v) != deviceRecordLen {
			return fmt.Errorf("store: 设备 %q 记录长度非法（%d 字节），拒绝撤销", id, len(v))
		}
		if v[0] == 1 {
			return nil // 已撤销，幂等
		}
		// 不得改写 Get 的返回值——bbolt 契约视其为只读内存映射页；需要变更就整条 Put。
		rec := append([]byte(nil), v...)
		rec[0] = 1
		return b.Put([]byte(id), rec)
	})
}

// SeenNonce 判定该端是否用过这条 nonce（防重放的读侧）。
func (s *Store) SeenNonce(deviceID, nonce string) (bool, error) {
	if err := validDeviceID(deviceID); err != nil {
		return false, err
	}
	if nonce == "" || bytes.ContainsRune([]byte(nonce), rune(keySep)) {
		return false, errors.New("store: nonce 非法")
	}
	var seen bool
	err := s.db.View(func(tx *bolt.Tx) error {
		seen = tx.Bucket(bucketReplay).Get(wrapKey(deviceID, nonce)) != nil
		return nil
	})
	return seen, err
}

// ClaimNonce 在单个写事务内完成「判重＋记录」：分开两步就成了
// check-then-act——120 s 窗内把同一条截获请求并发双发，两条都能通过去重。
// 返回 seen=true 表示这条 nonce 此前已见过（重放）。
func (s *Store) ClaimNonce(deviceID, nonce string) (seen bool, err error) {
	if err := validDeviceID(deviceID); err != nil {
		return false, err
	}
	if nonce == "" || bytes.ContainsRune([]byte(nonce), rune(keySep)) {
		return false, errors.New("store: nonce 非法")
	}
	key := wrapKey(deviceID, nonce)
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketReplay)
		if b.Get(key) != nil {
			seen = true
			return nil
		}
		if err := b.Put(key, []byte{1}); err != nil {
			return err
		}
		prefix := namePrefix(deviceID)
		var (
			n    int
			keep [][]byte
			c    = b.Cursor()
		)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			n++
			if !bytes.Equal(k, key) { // 刚插入的这条不参与驱逐，否则它可能被自己挤掉
				keep = append(keep, append([]byte(nil), k...))
			}
		}
		if n <= nonceRetentionPerDevice {
			return nil
		}
		for _, k := range keep[:n-nonceRetentionPerDevice] {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return seen, err
}

// NoteNonce 记录该端用过这条 nonce，并把每端保留量压回上界 512（有界增长）。
func (s *Store) NoteNonce(deviceID, nonce string) error {
	if err := validDeviceID(deviceID); err != nil {
		return err
	}
	if nonce == "" || bytes.ContainsRune([]byte(nonce), rune(keySep)) {
		return errors.New("store: nonce 非法")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketReplay)
		prefix := namePrefix(deviceID)
		if err := b.Put(wrapKey(deviceID, nonce), []byte{1}); err != nil {
			return err
		}
		var (
			n       int
			oldest  [][]byte
			c       = b.Cursor()
			maxKeep = nonceRetentionPerDevice
		)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			n++
			if len(oldest) < maxKeep {
				oldest = append(oldest, append([]byte(nil), k...))
			}
		}
		if n <= maxKeep {
			return nil
		}
		// 只保留最近 maxKeep 条：字典序最小者先删（键含 nonce 本身）。
		excess := n - maxKeep
		for i := 0; i < excess && i < len(oldest); i++ {
			if err := b.Delete(oldest[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

// PutPairing 写入一条配对码记录：键是码的 HMAC 索引，值里的 Record
// 必须是调用方加密后的载荷——库里因此既没有码明文，也没有未加密的过期信息。
func (s *Store) PutPairing(codeIndex string, p Pairing) error {
	if codeIndex == "" || len(p.Record) == 0 {
		return errors.New("store: 配对记录非法")
	}
	buf := make([]byte, 0, 1+8+len(p.Record))
	if p.Consumed {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(p.ExpiresAt))
	buf = append(buf, ts[:]...)
	buf = append(buf, p.Record...)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPairing).Put([]byte(codeIndex), buf)
	})
}

// Pairing 读取配对记录；未签发过的索引返回 ErrNotFound。
func (s *Store) Pairing(codeIndex string) (Pairing, error) {
	var p Pairing
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketPairing).Get([]byte(codeIndex))
		if v == nil {
			return fmt.Errorf("%w: 配对码", ErrNotFound)
		}
		if len(v) < 9 {
			return errors.New("store: 配对记录长度非法")
		}
		p.Consumed = v[0] == 1
		p.ExpiresAt = int64(binary.BigEndian.Uint64(v[1:9]))
		p.Record = append([]byte(nil), v[9:]...)
		return nil
	})
	return p, err
}

// MarkPairingConsumed 无条件置消费位（管理面与测试用）。不存在则报错。
func (s *Store) MarkPairingConsumed(codeIndex string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPairing)
		v := b.Get([]byte(codeIndex))
		if v == nil {
			return fmt.Errorf("%w: 配对码", ErrNotFound)
		}
		rec := append([]byte(nil), v...)
		rec[0] = 1
		return b.Put([]byte(codeIndex), rec)
	})
}

// Enroll 把一次登记做成一条写事务：判定配对码可用（存在／未消费／未过期）＋置消费位
// ＋顶替闸＋落设备记录。 bbolt 单写者把并发登记串行化，因此「一枚码只出一个端」与
// 「已在册端不被换掉签名公钥」都不依赖先查后写的顺序。
//
// 顶替闸按签名公钥判定，与撤销位无关：签名公钥相同 ⇒ 同一台端，允许换新加密公钥
// 并清撤销位（spec「被撤销的端重新登记后可再次取用」说的是持同一把签名私钥的真端）;
// 不同 ⇒ ErrDeviceExists，整笔回滚、码不被烧掉。
func (s *Store) Enroll(codeIndex, id string, dhPub, sigPub []byte) error {
	if err := validDeviceID(id); err != nil {
		return err
	}
	rec, err := encodeDevice(Device{ID: id, DhPub: dhPub, SigPub: sigPub})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket(bucketPairing)
		v := pb.Get([]byte(codeIndex))
		if v == nil {
			return fmt.Errorf("%w: 配对码", ErrNotFound)
		}
		if len(v) < 9 {
			return errors.New("store: 配对记录长度非法")
		}
		if v[0] == 1 {
			return ErrPairingConsumed
		}
		if time.Now().Unix() > int64(binary.BigEndian.Uint64(v[1:9])) {
			return ErrPairingExpired
		}
		dev := tx.Bucket(bucketDevices)
		if cur := dev.Get([]byte(id)); cur != nil {
			old, derr := decodeDevice(id, cur)
			if derr != nil {
				return derr
			}
			if !bytes.Equal(old.SigPub, sigPub) {
				return fmt.Errorf("%w: 设备 %q", ErrDeviceExists, id)
			}
		}
		consumed := append([]byte(nil), v...)
		consumed[0] = 1
		if err := pb.Put([]byte(codeIndex), consumed); err != nil {
			return err
		}
		return dev.Put([]byte(id), rec)
	})
}

// PairingSummary 是一条配对码记录的可见摘要（索引前缀＋时限＋消费位）。
type PairingSummary struct {
	Index     string
	ExpiresAt int64
	Consumed  bool
}

// ListPairings 枚举全部配对码记录（服务端本机管理面用，不含码本身）。
func (s *Store) ListPairings() ([]PairingSummary, error) {
	var out []PairingSummary
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPairing).ForEach(func(k, v []byte) error {
			if len(v) < 9 {
				return fmt.Errorf("store: 配对记录长度非法")
			}
			out = append(out, PairingSummary{
				Index:     string(k),
				ExpiresAt: int64(binary.BigEndian.Uint64(v[1:9])),
				Consumed:  v[0] == 1,
			})
			return nil
		})
	})
	return out, err
}

// RevokePairing 按索引前缀作废一枚未消费的配对码（管理面 pair revoke）。
// 前缀必须唯一命中一条未消费记录，否则 error（不猜是哪一枚）。
func (s *Store) RevokePairing(prefix string) error {
	if prefix == "" {
		return errors.New("store: 配对码索引前缀不能为空")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPairing)
		c := b.Cursor()
		var found [][]byte
		for k, v := c.Seek([]byte(prefix)); k != nil && bytes.HasPrefix(k, []byte(prefix)); k, v = c.Next() {
			if len(v) > 0 && v[0] == 0 {
				found = append(found, append([]byte(nil), k...))
			}
		}
		if len(found) != 1 {
			return fmt.Errorf("store: 索引前缀 %q 命中 %d 条未消费配对码，需唯一命中", prefix, len(found))
		}
		return b.Delete(found[0])
	})
}
