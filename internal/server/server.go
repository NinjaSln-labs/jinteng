// Package server 是凭据服务的 HTTP 面 v2：登记（POST /v2/enroll）、名录
// （GET /v2/devices）、写入（POST /v2/secret）、取用（GET /v2/secret/{name}）、
// 撤销（POST /v2/device/revoke）；每个到达 API 路由的请求写一条取用事件
// （成功与被拒都写，outcome 区分）。v1 路由整体废除，不做版本协商。
// 除 enroll（由一次性配对码授权、新签名公钥自证）外，每个请求都必须携带
// 由该端签名私钥产生的有效签名、时间戳与 nonce——「调用者是谁」从声称
// 变成持有。
//
// 服务层是三道关口的唯一落点（store 层保持中立）：
//  1. 库路径由 DBPath() 构造，取值只来自 material.Dir()＋material.ServerDBFile，
//     调用方（serve 命令）必须经它打开 store；
//  2. POST /v2/secret 拒收 wraps 含未注册（400 unknown-device）或已撤销
//     （400 revoked-device）设备 id 的请求；拒绝发生在任何写入之前，既不留
//     悬空 wrap 副本，也不把新 DEK 封给已撤销端；
//  3. TLS 材料只经 tls.go 落 material.Dir() 下的清单内文件。
//
// 三类拒绝可区分：未注册设备 ⇒ 401 unauthorized-device；已撤销设备 ⇒
// 403 revoked；凭据名不存在 ⇒ 404 not-found。被拒响应体只含 {"error": code}，
// 不回显凭据值、密文片段或 wrap 字节；成功取用响应只回密文信封与该端 wrap
// （均为已加密材料——明文由客户端封存，从不过服务端）。
// 凭据值／口令／DEK／私钥不进 error 文本、不进事件、不进日志。
package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/audit"
	"github.com/NinjaSln-labs/jinteng/internal/crypto"
	"github.com/NinjaSln-labs/jinteng/internal/material"
	"github.com/NinjaSln-labs/jinteng/internal/sign"
	"github.com/NinjaSln-labs/jinteng/internal/store"
)

// defaultListen 是缺省监听地址；只绑回环，绝不 0.0.0.0。
const defaultListen = "127.0.0.1:8787"

// maxBodyBytes 是请求体上限（本机凭据值很小；防超大 body 拖垮服务）。
// ponytail: 固定 1 MiB，v0 够用；将来放大要改流式解码。
const maxBodyBytes = 1 << 20

// 响应错误码（审查要求：拒绝必须可区分）。
const (
	codeBadRequest    = "bad-request"    // JSON 坏、body 超限、store 校验拒绝等
	codeBadDeviceKey  = "bad-device-key" // 退化 dhPub（全零或长度≠32B）
	codeBadSigKey     = "bad-sig-key"    // 退化 sigPub（全零或长度≠32B）
	codeUnknownDevice = "unknown-device" // wrap 含未注册设备 id
	codeUnauthDevice  = "unauthorized-device"
	codeNotFound      = "not-found"
	codeDeviceExists  = "device-exists"     // 重复注册（无有效配对码路径）
	codeWrapMissing   = "wrap-missing"      // 名存在但该端无 wrap 副本（不可达）
	codeAuditFailed   = "audit-failed"      // 事件写不进去 ⇒ fail-closed，不发业务结果
	codeBadSignature  = "bad-signature"     // 签名头残缺或验不通
	codeStaleRequest  = "stale-request"     // 时间窗超出
	codeReplayed      = "replayed"          // nonce 已见过
	codeDeviceRevoked = "device-revoked"    // 已撤销端
	codeInvalidPair   = "invalid-pair-code" // 配对码缺失／用过／过期
	codeRevokedWrap   = "revoked-device"    // wraps 里出现已撤销端（不得再发新 DEK）
	codeRevokeForeign = "revoke-foreign"    // 网络面只可撤销自己那端
)

// v2 签名头。三件都进入签名串（sign.CanonicalWithHeaders）。
const (
	headerDevice = "X-Jinteng-Device"
	headerTs     = "X-Jinteng-Ts"
	headerNonce  = "X-Jinteng-Nonce"
	headerSig    = "X-Jinteng-Sig"
)

// ctxDevice 是验签通过后写入请求上下文的设备身份——业务面只信它，
// 不再信 body 里自声明的 device_id。
type ctxKey int

const ctxDevice ctxKey = iota

// 事件 action 与 outcome 取值（事件动作枚举;devices＝名录读取,v2 新增）。
const (
	actionEnroll  = "enroll"
	actionPut     = "put"
	actionGet     = "get"
	actionRevoke  = "revoke"
	actionDevices = "devices"

	outcomeOK     = "ok"
	outcomeDenied = "denied"
)

// Options 是服务面可选项。零值可用：Listen 缺省 127.0.0.1:8787，
// Out 缺省 os.Stdout（证书指纹打印目标，测试注入缓冲区）。
type Options struct {
	Listen string
	Out    io.Writer
	// In 是 serve 终端的管理通道（配对码签发／列举／作废）。nil ⇒ 不启用。
	// 为什么必须有这条道：bbolt 是单写者库,服务在跑时第二个进程打不开写锁,
	// 而「给新端发一枚配对码」恰恰要发生在服务在跑的时候。
	In io.Reader
}

// Server 把单个 *store.Store（bbolt 单写者锁，全进程一个实例）暴露为 HTTP 面。
// libKey 是服务端库密钥：命名密钥化与事件盲索引都由它派生。
type Server struct {
	st       *store.Store
	libKey   []byte
	opts     Options
	mux      *http.ServeMux
	certPath string // Prepare 后有效
	keyPath  string // Prepare 后有效
}

// DBPath 构造服务端库路径：material.Dir() ＋ material.ServerDBFile，
// 不写死字面量。调用方打开 store 必须用本函数返回值。
func DBPath() (string, error) {
	dir, err := material.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, material.ServerDBFile), nil
}

// BlindIndex 由服务端库密钥对凭据名派生 HMAC-SHA256 索引（密钥化盲索引）：
// 它既是库内查找键，也是事件里的 name_blind_index。
// 客户端写 run 事件必须用同一把 library.key 调本函数，两侧才构造一致。
// 明文名绝不进事件；无库密钥者列不出名。
func BlindIndex(libKey []byte, name string) (string, error) {
	if name == "" {
		return "", errors.New("server: 凭据名不能为空")
	}
	return crypto.NameIndex(libKey, []byte(name))
}

// namePattern 是凭据命名的系统级规则（2.3）：只允许 [A-Za-z0-9_]，长度 1-64。
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// ValidName 是命名规则的唯一实现（单一事实源，供 client 与 server 共用）：
// 服务层在调用 PutSecret 之前用它拒绝非法名，客户端 Put/Take/Run 用同一个函数
// 做「早于网络」的前置校验——两侧跑同一条规则，才不存在「API 写进去、本端
// Take 取不出来」的名。
//
// 落点选本包的理由：客户端已经依赖 server（DBPath／BlindIndex），不新增任何
// 依赖边；store 层保持中立，只做结构性键校验（空名、复合键分隔符），
// 不承担产品命名策略。error 文本只含规则本身，不含值。
func ValidName(name string) error {
	if !namePattern.MatchString(name) {
		return errors.New("server: 非法凭据名（规则 [A-Za-z0-9_]{1,64}）")
	}
	return nil
}

// New 构造服务面并挂好路由。不触碰磁盘（TLS 材料由 Prepare/Listen 生成）。
// libKey 必须为 32 B（调用方经 material.LibraryKey() 取得）。
func New(st *store.Store, libKey []byte, opts Options) *Server {
	if opts.Listen == "" {
		opts.Listen = defaultListen
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	s := &Server{st: st, libKey: libKey, opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v2/devices", s.auth(actionDevices, s.handleDevices))
	mux.HandleFunc("POST /v2/secret", s.auth(actionPut, s.handlePut))
	mux.HandleFunc("GET /v2/secret/{name}", s.auth(actionGet, s.handleTake))
	mux.HandleFunc("POST /v2/device/revoke", s.auth(actionRevoke, s.handleRevoke))
	s.mux = mux
	return s
}

// blind 是本服务实例的索引派生入口（与 BlindIndex 同一实现）。
func (s *Server) blind(name string) (string, error) { return BlindIndex(s.libKey, name) }

// Handler 返回挂载了 v2 路由的 http.Handler，供 Listen 之外（测试）复用。
func (s *Server) Handler() http.Handler { return s.mux }

// auth 是 v2 的统一验签关口。顺序固定且如实可查：头齐备 → 时间窗 →
// 名录查该端（未登记 401 unknown-device）→ 验签（401 bad-signature）→ 撤销位
// （403 device-revoked）→ nonce 去重（403 replayed；判定落库，重启后仍成立）→
// 记 nonce → 放行。任何一步的被拒都发生在业务读取之前——拒绝早于任何密文出网。
// enroll 不走本关口：它的签名由「请求体里那把尚未登记的 sig_pub」产生，自证在
// handleEnroll 内完成（「验签即验证」）。
func (s *Server) auth(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		body, ok := readBodyBytes(r)
		if !ok {
			s.reply(w, action, r.Header.Get(headerDevice), name, http.StatusBadRequest, codeBadRequest)
			return
		}
		deviceID := r.Header.Get(headerDevice)
		nonce := r.Header.Get(headerNonce)
		ts, tsErr := strconv.ParseInt(r.Header.Get(headerTs), 10, 64)
		h := sign.Header{Device: deviceID, Ts: ts, Nonce: nonce, Sig: r.Header.Get(headerSig)}
		deny := func(status int, code string) { s.reply(w, action, deviceID, name, status, code) }

		if deviceID == "" || nonce == "" || h.Sig == "" || tsErr != nil {
			deny(http.StatusUnauthorized, codeBadSignature)
			return
		}
		if !sign.CheckWindow(ts, time.Now()) {
			deny(http.StatusUnauthorized, codeStaleRequest)
			return
		}
		dev, err := s.st.Device(deviceID)
		if err != nil {
			deny(http.StatusUnauthorized, codeUnknownDevice)
			return
		}
		canonical := sign.CanonicalWithHeaders(h, r.Method, r.URL.Path, r.URL.Query(), body)
		if !sign.Verify(dev.SigPub, h, canonical) {
			deny(http.StatusUnauthorized, codeBadSignature)
			return
		}
		if dev.Revoked {
			deny(http.StatusForbidden, codeDeviceRevoked)
			return
		}
		seen, err := s.st.ClaimNonce(deviceID, nonce) // 判重与记录同一事务（防并发双发）
		if err != nil {
			deny(http.StatusInternalServerError, codeAuditFailed)
			return
		}
		if seen {
			deny(http.StatusForbidden, codeReplayed)
			return
		}
		r2 := r.WithContext(context.WithValue(r.Context(), ctxDevice, deviceID))
		r2.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r2)
	}
}

// identityOf 取验签通过后放进上下文的设备身份——业务面唯一的身份来源，
// 请求体里自声明的 device_id 不再参与判定。
func identityOf(r *http.Request) string {
	id, _ := r.Context().Value(ctxDevice).(string)
	return id
}

// Listen 校验监听地址、生成/复用 TLS 材料后开始 TLS 监听。
// 地址写不明白（空 host／未指定地址／无法解析）在 Prepare 与 bind 之前拒绝。
func (s *Server) Listen() error {
	if err := parseListenAddr(s.opts.Listen); err != nil {
		return err
	}
	if err := s.Prepare(); err != nil {
		return err
	}
	if s.opts.In != nil {
		go s.handleControl(s.opts.In)
	}
	return http.ListenAndServeTLS(s.opts.Listen, s.certPath, s.keyPath, s.mux)
}

// ---- 线格式 v2（身份一律来自签名头；b64 一律 std encoding）----
//
// POST /v2/enroll  {"device_id":s,"dh_pub":b64,"sig_pub":b64,"pair_code":s}   → 200 {"status":"enrolled"}
//                  唯一不经名录验签的路由：签名由请求体里那把新 sig_pub 自证，
//                  登记资格由一次性配对码授权。
// GET  /v2/devices （签名）                                                    → 200 {"devices":[{id,revoked,dh_pub,sig_pub}]}
// POST /v2/secret  {"name":s,"ciphertext":b64,"wraps":{deviceID:b64,…}}        → 200 {"status":"stored"}
// GET  /v2/secret/{name} （签名）                                              → 200 {"ciphertext":b64,"wrap":b64}
// POST /v2/device/revoke {"device_id":s}（签名；body 是被撤销的目标端）        → 200 {"status":"revoked"}
// 所有非 2xx：{"error": <code>}。请求体里不再有自声明的调用方身份。

type enrollRequest struct {
	DeviceID string `json:"device_id"`
	DhPub    string `json:"dh_pub"`
	SigPub   string `json:"sig_pub"`
	PairCode string `json:"pair_code"`
}

type putRequest struct {
	Name       string            `json:"name"`
	Ciphertext string            `json:"ciphertext"`
	Wraps      map[string]string `json:"wraps"`
}

type revokeRequest struct {
	DeviceID string `json:"device_id"` // 被撤销的目标端（调用方身份来自签名头）
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	body, ok := readBodyBytes(r)
	if !ok {
		s.reply(w, actionEnroll, "", "", http.StatusBadRequest, codeBadRequest)
		return
	}
	var req enrollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.reply(w, actionEnroll, "", "", http.StatusBadRequest, codeBadRequest)
		return
	}
	if r.Body != nil {
		io.Copy(io.Discard, r.Body)
	}
	dhPub, err := base64.StdEncoding.DecodeString(req.DhPub)
	// 注册面防线：拒退化值——base64 坏、全零或长度≠32 B。天花板如实声明：
	// 标准库不提供 X25519 完整曲线点验证，这里只拒退化值，不声称已做曲线校验；
	// 低阶等退化值由全零/长度检查、curve25519 对全零的拒绝与 WrapDEK 内部
	// ECDH 全零输出检查共同兜住。
	if err != nil || len(dhPub) != crypto.KeyLen || isAllZero(dhPub) {
		s.reply(w, actionEnroll, req.DeviceID, "", http.StatusBadRequest, codeBadDeviceKey)
		return
	}
	sigPub, err := base64.StdEncoding.DecodeString(req.SigPub)
	if err != nil || len(sigPub) != ed25519.PublicKeySize || isAllZero(sigPub) {
		s.reply(w, actionEnroll, req.DeviceID, "", http.StatusBadRequest, codeBadSigKey)
		return
	}
	// 「验签即验证」：用请求自带的 sig_pub 验这条请求自己的签名——合法点校验由
	// 标准库在验签时天然完成，不需要第三方曲线库。签名串必须与客户端算法一致。
	deviceID := r.Header.Get(headerDevice)
	nonce := r.Header.Get(headerNonce)
	ts, tsErr := strconv.ParseInt(r.Header.Get(headerTs), 10, 64)
	h := sign.Header{Device: deviceID, Ts: ts, Nonce: nonce, Sig: r.Header.Get(headerSig)}
	if deviceID == "" || nonce == "" || h.Sig == "" || tsErr != nil || !sign.CheckWindow(ts, time.Now()) {
		s.reply(w, actionEnroll, deviceID, "", http.StatusUnauthorized, codeBadSignature)
		return
	}
	// 身份只有一个来源：体侧 device_id 必须等于被签名覆盖的头里的 device_id，
	// 否则「自证的是这把钥」与「登记到哪个端」会各说各话。
	if req.DeviceID != deviceID {
		s.reply(w, actionEnroll, req.DeviceID, "", http.StatusUnauthorized, codeBadSignature)
		return
	}
	canonical := sign.CanonicalWithHeaders(h, r.Method, r.URL.Path, r.URL.Query(), body)
	if !sign.Verify(sigPub, h, canonical) {
		s.reply(w, actionEnroll, deviceID, "", http.StatusUnauthorized, codeBadSignature)
		return
	}
	// 顶替闸与配对码消费、落库在同一条写事务里（store.Enroll）：先查后写时，并发
	// 的两次登记能让后者无条件覆写前者的公钥。闸按签名公钥判定，与撤销位无关——
	// 签名公钥是端的身份锚，换它就不是「同一台端重新登记」。
	if err := s.enrollWithCode(req.PairCode, req.DeviceID, dhPub, sigPub); err != nil {
		switch {
		case errors.Is(err, store.ErrDeviceExists):
			s.reply(w, actionEnroll, req.DeviceID, "", http.StatusForbidden, codeDeviceExists)
		case errors.Is(err, store.ErrNotFound),
			errors.Is(err, store.ErrPairingConsumed),
			errors.Is(err, store.ErrPairingExpired):
			s.reply(w, actionEnroll, req.DeviceID, "", http.StatusForbidden, codeInvalidPair)
		default:
			s.reply(w, actionEnroll, req.DeviceID, "", http.StatusBadRequest, codeBadRequest)
		}
		return
	}
	s.replyOK(w, actionEnroll, req.DeviceID, "", map[string]string{"status": "enrolled"})
}

// handleDevices 返回设备名录：只有 id／撤销位与两把公钥。
// 它是名录不是可解密材料——公钥与状态位在任何模型下都不是秘密。
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.st.ListDevices()
	if err != nil {
		s.reply(w, actionDevices, identityOf(r), "", http.StatusBadRequest, codeBadRequest)
		return
	}
	out := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		out = append(out, map[string]any{
			"id":      d.ID,
			"revoked": d.Revoked,
			"dh_pub":  base64.StdEncoding.EncodeToString(d.DhPub),
			"sig_pub": base64.StdEncoding.EncodeToString(d.SigPub),
		})
	}
	s.replyOK(w, actionDevices, identityOf(r), "", map[string]any{"devices": out})
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	caller := identityOf(r)
	var req putRequest
	if !decodeBody(r, &req) {
		s.reply(w, actionPut, caller, "", http.StatusBadRequest, codeBadRequest)
		return
	}
	name := req.Name
	index, err := s.blind(name)
	if err != nil {
		s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeBadRequest)
		return
	}
	// 命名关口（系统级不变量）：非法名必须在任何写入之前由服务层拒绝。过去这条
	// 规则只在客户端强制，直接打 API 能把含 '-' 或超 64 字符的名落库。store 保持
	// 中立，这道关落在服务层；被拒时密文与 wrap 一个字节都不写。
	if err := ValidName(name); err != nil {
		s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeBadRequest)
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeBadRequest)
		return
	}
	wraps := make(map[string][]byte, len(req.Wraps))
	for id, enc := range req.Wraps {
		b, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeBadRequest)
			return
		}
		wraps[id] = b
	}
	// 悬空 wrap 关口＋已撤销端不得拿到新 DEK 副本：两条都由 store.PutSecret 在
	// 同一条写事务内判定（见该函数注释）,被拒时密文与 wrap 一个字节都不落库。
	// 真名只以密文入库：库文件单独外流时列不出凭据名。
	nameCipher, err := crypto.SealName(s.libKey, []byte(name))
	if err != nil {
		s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeBadRequest)
		return
	}
	if err := s.st.PutSecret(index, nameCipher, ct, wraps); err != nil {
		switch {
		case errors.Is(err, store.ErrDeviceRevoked):
			s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeRevokedWrap)
		case errors.Is(err, store.ErrNotFound):
			s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeUnknownDevice)
		default:
			s.reply(w, actionPut, caller, name, http.StatusBadRequest, codeBadRequest)
		}
		return
	}
	s.replyOK(w, actionPut, caller, name, map[string]string{"status": "stored"})
}

func (s *Server) handleTake(w http.ResponseWriter, r *http.Request) {
	caller := identityOf(r)
	name := r.PathValue("name")
	index, err := s.blind(name)
	if err != nil {
		s.reply(w, actionGet, caller, name, http.StatusBadRequest, codeBadRequest)
		return
	}
	ct, wraps, err := s.st.GetSecret(index)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.reply(w, actionGet, caller, name, http.StatusNotFound, codeNotFound)
		} else {
			s.reply(w, actionGet, caller, name, http.StatusBadRequest, codeBadRequest)
		}
		return
	}
	devWrap, hasWrap := wraps[caller]
	if !hasWrap {
		// 名存在但该端没有 wrap 副本（如登记晚于写入）：不可达，区别于 404。
		s.reply(w, actionGet, caller, name, http.StatusForbidden, codeWrapMissing)
		return
	}
	s.replyOK(w, actionGet, caller, name, map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"wrap":       base64.StdEncoding.EncodeToString(devWrap),
	})
}

// handleRevoke 撤销目标端：只置撤销位（不重包），撤销后该端永远取不到
// 任何既有密文的 wrap——用同一对密钥重新登记会清撤销位并使旧 wrap 复通,彻底断绝
// 内容仍靠轮换凭据（不重包语义）。
//
// 信任边界（服务面暴露到本机之外必须先落请求签名）：调用方必须持有自己那端的签名私钥，
// 「任何能连上本机端口的人只要知道 device id 就能撤销」这条路已封死。
//
// 发起面：网络面只接受「撤销自己那端」;
// 撤他端属服务端操作员动作,走 serve 终端管理通道（与配对码签发同路）。
// 否则一枚泄露出去的配对码就能登记出一个可撤销全部健康端的端。
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	caller := identityOf(r)
	var req revokeRequest
	if !decodeBody(r, &req) {
		s.reply(w, actionRevoke, caller, "", http.StatusBadRequest, codeBadRequest)
		return
	}
	if req.DeviceID != caller {
		s.reply(w, actionRevoke, caller, "", http.StatusForbidden, codeRevokeForeign)
		return
	}
	if err := s.st.RevokeDevice(req.DeviceID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.reply(w, actionRevoke, caller, "", http.StatusNotFound, codeNotFound)
		} else {
			s.reply(w, actionRevoke, caller, "", http.StatusBadRequest, codeBadRequest)
		}
		return
	}
	s.replyOK(w, actionRevoke, caller, "", map[string]string{"status": "revoked"})
}

// readBodyBytes 读取请求体（≤maxBodyBytes）；超限或读失败返回 false。
func readBodyBytes(r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		return nil, false
	}
	return body, true
}

// decodeBody 解验签关口放回内存的请求体；空体、坏 JSON 返回 false。
func decodeBody(r *http.Request, v any) bool {
	body, ok := readBodyBytes(r)
	if !ok || len(body) == 0 {
		return false
	}
	return json.Unmarshal(body, v) == nil
}

// replyOK 写 ok 事件并回 200。
func (s *Server) replyOK(w http.ResponseWriter, action, deviceID, name string, payload any) {
	s.write(w, action, deviceID, name, http.StatusOK, payload)
}

// reply 写 denied 事件并回错误码：响应体为 {"error": codeErr}，只含码本身。
func (s *Server) reply(w http.ResponseWriter, action, deviceID, name string, status int, codeErr string) {
	s.write(w, action, deviceID, name, status, map[string]string{"error": codeErr})
}

// write 是唯一出口。副作用顺序必须如实陈述：业务 store 变更（AddDevice／
// PutSecret／RevokeDevice）在进入本函数之前已经提交，事件写发生在响应发出
// 之前——即「业务变更先提交，事件写在响应之前」，不是「先落事件、再落业务」。
// 事件写不进（含 blind index 派生失败）一律 fail-closed 为 500 audit-failed，
// 不发业务结果——本产品的可观测性承诺不允许「结果已发但事件缺失」；但已提交
// 的 store 变更不回滚。由此得到重试语义：put 同名覆盖幂等、
// revoke 重复撤销幂等；enroll 的配对码在受理前已被消费，因此「500 但已注册」
// 之后重试必须重新签发一枚配对码（不是报 device-exists 就能续上的路径）。
// payload 只含状态/错误码/密文材料，绝不含明文。
func (s *Server) write(w http.ResponseWriter, action, deviceID, name string, status int, payload any) {
	outcome := outcomeOK
	if status >= 400 {
		outcome = outcomeDenied
	}
	blind := ""
	var err error
	if name != "" {
		blind, err = s.blind(name)
	}
	if err == nil {
		err = audit.Write(audit.Event{
			TS: time.Now(), DeviceID: deviceID, Action: action,
			Outcome: outcome, NameBlindIndex: blind,
		})
	}
	if err != nil {
		status, payload = http.StatusInternalServerError, map[string]string{"error": codeAuditFailed}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}

// parseListenAddr 判定监听地址是否「足以确定监听身份」：必须写出 host，且 host
// 非未指定地址（0.0.0.0／:: 等于绑所有接口，不由缺省给出），主机名形式必须可解析。
//
// v2 改写：v1 时期这里拒一切非回环地址，因为「能连本机端口」就等于自声明身份;
// v2 每个请求都必须持签名私钥，回环不再是免签捷径，因此放开显式非回环绑定，
// 只保留「地址本身写不明白就 fail-closed」这条。
func parseListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("server: 非法监听地址（须为 host:port）")
	}
	if host == "" {
		return errors.New("server: 拒绝空 host（等于绑所有接口，请显式写出地址）")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return errors.New("server: 拒绝未指定地址（0.0.0.0／::，请显式写出本机可路由地址）")
		}
		return nil
	}
	if _, err := net.LookupIP(host); err != nil {
		return errors.New("server: 监听地址无法解析")
	}
	return nil
}
