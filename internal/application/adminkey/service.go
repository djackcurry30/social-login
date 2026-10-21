// Package adminkey 是管理端"签名密钥管理（F 组）"用例。
//
// 交付范围（架构 §15.4 F 组 / §8.3）：
//
//	GET  /admin/v1/signing-keys                密钥列表
//	POST /admin/v1/signing-keys/rotate         轮换第 1·2 步：新密钥签名 + 旧密钥留在 JWKS
//	POST /admin/v1/signing-keys/{kid}/retire   轮换第 3·4 步：下线旧密钥
//	GET  /admin/v1/signing-keys/jwks-preview   预览 JWKS
//
// 这把 §8.3 的"四步轮换"变成两个按钮。**两个按钮之间的等待是必须的**：
// retire 的前置校验（不得存在用该 kid 签发且未过期的 token）不是可选项，
// 它防的是"一怒之下把旧密钥下线，结果全站旧 token 立刻验签失败"。
package adminkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/admin"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
	"github.com/djackcurry30/social-login/internal/pkg/jwtkit"
)

// KeyStore 是密钥持久化端口（实现见 jwtkit.FileStore）。
//
// 抽出接口是为了把"私钥存哪"与"什么时候轮换"解耦：将来换 KMS 时
// 只需要新的实现，用例层不动。
type KeyStore interface {
	Save(activeKID string, states []jwtkit.KeyState) error
}

// Deps 是用例依赖。
type Deps struct {
	Signer     *jwtkit.Signer
	Store      KeyStore
	AdminAudit admin.AuditWriter
	Logger     *zap.Logger
	Now        func() time.Time
}

// Service 是 F 组用例入口。
type Service struct {
	deps Deps
}

// New 构造服务。
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{deps: d}
}

// List 返回密钥列表。
func (s *Service) List(ctx context.Context) ([]jwtkit.KeyInfo, error) {
	_ = ctx
	return s.deps.Signer.List(), nil
}

// JWKSPreview 返回当前 /v1/jwks 会返回的内容。
//
// 轮换后核对用：运维点完 rotate，先看一眼预览确认新旧两把都在，
// 再去改业务方的缓存策略。
func (s *Service) JWKSPreview(ctx context.Context) ([]byte, error) {
	_ = ctx
	return s.deps.Signer.JWKS()
}

// RotateOutput 是轮换结果。
type RotateOutput struct {
	// NewKID 是开始签名的新密钥。
	NewKID string `json:"new_kid"`
	// PreviousKID 是降级为"仅发布"的旧密钥（首次轮换时为空）。
	PreviousKID string `json:"previous_kid,omitempty"`
	// RetirableAt 是旧密钥可以下线的最早时刻。
	//
	// 前端据此显示"X 分钟后可下线"，而不是让运维自己记住要等 15 分钟。
	RetirableAt *time.Time `json:"retirable_at,omitempty"`
	// PublishedKeys 是轮换后 JWKS 中公钥的数量（正常应为 2：新旧各一把）。
	PublishedKeys int `json:"published_keys"`
}

// Rotate 生成新密钥并开始签名（§8.3 第 1·2 步）。
//
// 顺序上先落盘再切换内存：落盘失败时内存保持原状，不会出现"进程里换了、
// 重启后又变回去"的错配。
func (s *Service) Rotate(ctx context.Context, reason string, p *admin.Principal) (*RotateOutput, error) {
	if len([]rune(reason)) < 4 {
		return nil, errs.New(errs.CodeAdminReasonRequired, "密钥轮换必须填写 reason（≥4 字符）")
	}

	if s.deps.Store == nil {
		// 不能只改内存：那样重启后轮换就失效，运维以为换了密钥，
		// 实际 JWKS 又回到旧的那把。宁可明确拒绝。
		return nil, errs.New(errs.CodeConfigInvalid,
			"未配置签名密钥存储（security.key_dir），无法持久化轮换结果").
			WithDetail("hint", "配置 security.key_dir 后重试")
	}

	now := s.deps.Now()
	kid := newKID(now)
	key, err := jwtkit.GenerateKey(kid)
	if err != nil {
		return nil, err
	}
	key.CreatedAt = now

	// 先算出"轮换之后"的完整状态并落盘。
	activeKID, states := s.deps.Signer.Snapshot()
	next := make([]jwtkit.KeyState, 0, len(states)+1)
	for _, st := range states {
		if st.KID == activeKID && st.DemotedAt.IsZero() {
			st.DemotedAt = now
		}
		next = append(next, st)
	}
	next = append(next, jwtkit.KeyState{
		KID: key.KID, Private: key.Private, CreatedAt: now,
	})
	if err := s.deps.Store.Save(kid, next); err != nil {
		s.writeAudit(ctx, p, "key.rotate", kid, reason, "error")
		return nil, errs.Wrap(errs.CodeInternal,
			"新密钥落盘失败，已放弃本次轮换（内存未切换）", err)
	}

	prev, err := s.deps.Signer.Rotate(key)
	if err != nil {
		s.writeAudit(ctx, p, "key.rotate", kid, reason, "error")
		return nil, err
	}

	s.writeAudit(ctx, p, "key.rotate", kid, reason, "success")
	s.logger().Warn("签名密钥已轮换",
		zap.String("new_kid", kid),
		zap.String("previous_kid", prev),
		zap.String("reason", reason))

	out := &RotateOutput{NewKID: kid, PreviousKID: prev, PublishedKeys: len(s.deps.Signer.Kids())}
	if prev != "" {
		r := now.Add(s.deps.Signer.TTL() + time.Minute)
		out.RetirableAt = &r
	}
	return out, nil
}

// Retire 下线旧密钥（§8.3 第 3·4 步）。
//
// 前置校验在 Signer 里：不得存在用该 kid 签发且未过期的 token
// （按"停签时刻 + access TTL"推算）。这里不再重复判断，避免两处口径分叉。
func (s *Service) Retire(ctx context.Context, kid, reason string, p *admin.Principal) error {
	if kid == "" {
		return errs.New(errs.CodeInvalidRequest, "kid 不能为空")
	}
	if len([]rune(reason)) < 4 {
		return errs.New(errs.CodeAdminReasonRequired, "密钥下线必须填写 reason（≥4 字符）")
	}

	if s.deps.Store == nil {
		return errs.New(errs.CodeConfigInvalid,
			"未配置签名密钥存储（security.key_dir），无法持久化下线结果")
	}
	if err := s.deps.Signer.Retire(kid); err != nil {
		s.writeAudit(ctx, p, "key.retire", kid, reason, "error")
		return err
	}

	// 内存已下线。落盘失败时宁可留下"文件里还有这把旧密钥"——
	// 那是更保守的失败方向：重启后它继续发布公钥，不会让旧 token 验签失败。
	active, states := s.deps.Signer.Snapshot()
	if err := s.deps.Store.Save(active, states); err != nil {
		s.logger().Error("密钥下线后落盘失败：重启后该密钥会重新出现在 JWKS",
			zap.String("kid", kid), zap.Error(err))
	}

	s.writeAudit(ctx, p, "key.retire", kid, reason, "success")
	s.logger().Warn("签名密钥已下线", zap.String("kid", kid), zap.String("reason", reason))
	return nil
}

// newKID 生成可读的 kid：k-YYYYMMDD-<6hex>。
//
// 带日期是为了排障时一眼看出"这把是哪天启用的"，随机后缀保证唯一。
func newKID(now time.Time) string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 随机失败时退化为纳秒后缀：kid 只需要唯一，不需要密码学强度。
		return fmt.Sprintf("k-%s-%06d", now.Format("20060102"), now.Nanosecond()%1_000_000)
	}
	return fmt.Sprintf("k-%s-%s", now.Format("20060102"), hex.EncodeToString(b[:]))
}

func (s *Service) writeAudit(ctx context.Context, p *admin.Principal, action, kid, reason, result string) {
	if s.deps.AdminAudit == nil {
		return
	}
	e := &admin.AuditEvent{
		Action:     action,
		TargetType: "signing_key",
		TargetID:   kid,
		Reason:     reason,
		Result:     result,
	}
	e.SubjectID = "admin:anonymous"
	if p != nil && p.User != nil {
		e.SubjectID = fmt.Sprintf("admin:%d", p.User.ID)
	}
	_ = s.deps.AdminAudit.Write(ctx, e)
}

func (s *Service) logger() *zap.Logger {
	if s.deps.Logger == nil {
		return zap.NewNop()
	}
	return s.deps.Logger
}
