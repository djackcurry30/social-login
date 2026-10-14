package token

import (
	"context"
	"time"

	"github.com/alex/social-login/internal/domain/identity"
	"github.com/alex/social-login/internal/domain/session"
	"github.com/alex/social-login/internal/pkg/errs"
	"github.com/alex/social-login/internal/pkg/jwtkit"
)

// BoundIdentity 是"绑定关系已确立后直接签发令牌"所需的要素。
type BoundIdentity struct {
	AppCode        string
	ExternalUserID string
	DeviceID       string
	// Scope 留空取默认值（openid profile）。
	Scope string
	AMR   []string
}

// IssueForBoundIdentity 在绑定成功后直接签发一对令牌。
//
// 之所以暴露这个方法而不是让调用方自己拼 Response：签发路径必须保持唯一。
// 一旦出现第二条签发路径，就很容易漏掉"撤销旧会话""写 refresh_token"这类步骤，
// 而这类遗漏只会在生产环境的会话数量对不上时才被发现。
func (s *Service) IssueForBoundIdentity(ctx context.Context, in BoundIdentity) (*Response, error) {
	if in.ExternalUserID == "" {
		return nil, errs.New(errs.CodeInternal, "签发令牌缺少账号标识")
	}
	app, err := s.deps.Tenant.Application(ctx, in.AppCode)
	if err != nil {
		return nil, err
	}
	scope := in.Scope
	if scope == "" {
		scope = identity.ScopeOpenIDProfile
	}

	accessToken, claims, err := s.deps.Signer.Issue(jwtkit.IssueInput{
		Subject:  in.ExternalUserID,
		Audience: app.AppCode,
		Scope:    scope,
		AMR:      in.AMR,
		TTL:      s.cfg.AccessTokenTTL,
	})
	if err != nil {
		return nil, err
	}

	raw, err := s.newOpaqueToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err := s.deps.Sessions.Create(ctx, session.CreateInput{
		AppID:          app.ID,
		ExternalUserID: in.ExternalUserID,
		TokenHash:      session.HashToken(raw),
		DeviceID:       in.DeviceID,
		Scope:          scope,
		ExpiresAt:      now.Add(s.cfg.RefreshTokenTTL),
		At:             now,
	}); err != nil {
		return nil, err
	}

	return &Response{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: raw,
		Scope:        scope,
		Subject:      in.ExternalUserID,
		AMR:          claims.AMR,
	}, nil
}
