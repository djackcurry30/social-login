package postgres

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/alex/social-login/internal/domain/session"
	"github.com/alex/social-login/internal/pkg/appctx"
	"github.com/alex/social-login/internal/pkg/errs"
)

// 轮转链回溯的安全上限。
//
// 正常情况下链长等于"该设备刷新过多少次"，几百次已属异常；
// 加上限是为了防止数据异常（例如人为构造的环）造成无限循环。
const maxRotationChainDepth = 1000

// SessionRepository 是 refresh_tokens 表的仓储。
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository 构造仓储。
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

var _ session.Repository = (*SessionRepository)(nil)

// Create 写入一条刷新令牌。
func (r *SessionRepository) Create(ctx context.Context, in session.CreateInput) (*session.RefreshToken, error) {
	if in.AppID <= 0 || in.ExternalUserID == "" || in.TokenHash == "" {
		return nil, errs.New(errs.CodeInternal, "刷新令牌写入参数不完整")
	}
	at := in.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = appctx.WithAppScope(ctx, in.AppID)

	m := refreshTokenModel{
		AppID:          in.AppID,
		ExternalUserID: in.ExternalUserID,
		TokenHash:      in.TokenHash,
		DeviceID:       in.DeviceID,
		Scope:          in.Scope,
		ExpiresAt:      in.ExpiresAt,
		RotatedFrom:    in.RotatedFrom,
		CreatedAt:      at,
	}
	if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "写入刷新令牌失败", err)
	}
	return tokenToDomain(&m), nil
}

// FindByHash 按哈希查找刷新令牌。
func (r *SessionRepository) FindByHash(ctx context.Context, appID int64, tokenHash string) (*session.RefreshToken, error) {
	if appID <= 0 || tokenHash == "" {
		return nil, session.ErrNotFound
	}
	ctx = appctx.WithAppScope(ctx, appID)

	var m refreshTokenModel
	err := r.db.WithContext(ctx).
		Where("app_id = ? AND token_hash = ?", appID, tokenHash).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "查询刷新令牌失败", err)
	}
	return tokenToDomain(&m), nil
}

// Revoke 撤销单条令牌。
func (r *SessionRepository) Revoke(ctx context.Context, appID, id int64, reason string) error {
	if appID <= 0 || id <= 0 {
		return errs.New(errs.CodeInternal, "撤销令牌参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	res := r.db.WithContext(ctx).Model(&refreshTokenModel{}).
		Where("app_id = ? AND id = ? AND revoked = false", appID, id).
		Updates(map[string]any{"revoked": true, "revoked_reason": reason})
	if res.Error != nil {
		return errs.Wrap(errs.CodeInternal, "撤销刷新令牌失败", res.Error)
	}
	return nil
}

// revokeChainSQL 以给定令牌为根，沿轮转链撤销整条会话。
//
// ⚠️ 这里有一处方向性错误，是第一期验收测试发现的，值得记下来：
//
// 轮转链的指针方向是【新令牌 → 旧令牌】（rotated_from），也就是说
// rotated_from 是一条"指向父亲"的边。而"整条会话链"要撤销的是【该令牌及其
// 全部后代】——因为被泄露的旧令牌所派生出的每一个新令牌，都可能是攻击者手里的
// 那个。所以正确的遍历方向是【由根向后代展开】，而不是"向上回溯祖先"。
//
// 早期实现按"向上回溯"写，结果是：用户重放已轮转的 rt1 时，只撤销了 rt1，
// 而攻击者/用户手里那个由 rt1 派生的 rt2 依然可用——重放检测完全失效。
// 这类错误不会在任何"正常路径"测试里暴露，只有专门构造重放场景才会命中。
//
// 用一条递归 CTE 而不是多次查询：单条语句即原子完成，避免"撤销了一半"的中间态。
// depth 上限是防御性的——正常链长等于该设备刷新过多少次，不可能到千级。
const revokeChainSQL = `
WITH RECURSIVE chain AS (
    SELECT id, 1 AS depth
    FROM refresh_tokens
    WHERE app_id = $1 AND id = $2
    UNION ALL
    SELECT t.id, c.depth + 1
    FROM refresh_tokens t
    JOIN chain c ON t.rotated_from = c.id
    WHERE t.app_id = $1 AND c.depth < $4
)
UPDATE refresh_tokens
SET revoked = true, revoked_reason = $3
WHERE app_id = $1
  AND revoked = false
  AND id IN (SELECT id FROM chain)`

// RevokeChainFrom 撤销以该令牌为根的整条轮转链（含其全部后代）。
//
// 用途：Refresh Token Reuse Detection（架构 §8.2）。当检测到某个已轮转的令牌
// 被重复使用，说明它极可能已被窃取——攻击者与真实用户各持一份。此时唯一安全的
// 动作是把该会话派生出的全部令牌作废，强制重新登录。
func (r *SessionRepository) RevokeChainFrom(ctx context.Context, appID, id int64, reason string) (int, error) {
	if appID <= 0 || id <= 0 {
		return 0, errs.New(errs.CodeInternal, "撤销令牌链参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	// 说明：Raw SQL 不经过 GORM 的隔离回调（回调查不到 Clauses），
	// 因此 app_id 必须显式出现在 CTE 的【每个】分支与 UPDATE 条件上。
	// 这是 tech-stack 里那条"Raw 必须显式带 app_id"纪律的具体落点。
	res := r.db.WithContext(ctx).Exec(revokeChainSQL, appID, id, reason, maxRotationChainDepth)
	if res.Error != nil {
		return 0, errs.Wrap(errs.CodeInternal, "撤销令牌链失败", res.Error)
	}
	return int(res.RowsAffected), nil
}

// RevokeAllByUser 撤销某业务账号的全部令牌。
func (r *SessionRepository) RevokeAllByUser(ctx context.Context, appID int64, externalUserID, reason string) (int64, error) {
	if appID <= 0 || externalUserID == "" {
		return 0, errs.New(errs.CodeInternal, "撤销令牌参数不完整")
	}
	ctx = appctx.WithAppScope(ctx, appID)

	res := r.db.WithContext(ctx).Model(&refreshTokenModel{}).
		Where("app_id = ? AND external_user_id = ? AND revoked = false", appID, externalUserID).
		Updates(map[string]any{"revoked": true, "revoked_reason": reason})
	if res.Error != nil {
		return 0, errs.Wrap(errs.CodeInternal, "撤销用户全部令牌失败", res.Error)
	}
	return res.RowsAffected, nil
}

func tokenToDomain(m *refreshTokenModel) *session.RefreshToken {
	return &session.RefreshToken{
		ID:             m.ID,
		AppID:          m.AppID,
		ExternalUserID: m.ExternalUserID,
		TokenHash:      m.TokenHash,
		DeviceID:       m.DeviceID,
		Scope:          m.Scope,
		ExpiresAt:      m.ExpiresAt,
		RotatedFrom:    m.RotatedFrom,
		Revoked:        m.Revoked,
		RevokedReason:  m.RevokedReason,
		CreatedAt:      m.CreatedAt,
	}
}
