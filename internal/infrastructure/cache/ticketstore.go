package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/domain/ticket"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// Redis 键前缀（架构 §6.3）。
//
// 命名刻意把 "replay"（已消费票据指纹）与 Apple 的 nonce 区分开——
// 二者都叫"防重放"，但一个是本服务的票据指纹表，一个是平台侧的授权 nonce，
// 混用命名会在排障时误导人（修正 A16）。
const (
	keyPrefixContext    = "oauth:ticket:"
	keyPrefixAuthCode   = "oauth:code:"
	keyPrefixBindTicket = "oauth:bindticket:"
	// 待验证合并票据。与 bindticket 分开前缀：两者 TTL 与消费语义不同
	// （bindticket 读即删，merge ticket 只在验证完成时删）。
	keyPrefixMergeTicket = "oauth:mergeticket:"
	keyPrefixReplay      = "oauth:replay:"
)

// TicketStore 是 ticket.Store 的 Redis 实现。
type TicketStore struct {
	rdb *redis.Client
}

// NewTicketStore 构造票据存储。
func NewTicketStore(rdb *redis.Client) *TicketStore {
	return &TicketStore{rdb: rdb}
}

var _ ticket.Store = (*TicketStore)(nil)

// SaveContext 保存授权上下文。
func (s *TicketStore) SaveContext(ctx context.Context, c *ticket.Context, ttl time.Duration) error {
	if c == nil || c.State == "" {
		return errs.New(errs.CodeInternal, "授权上下文缺少 state")
	}
	if ttl <= 0 {
		ttl = ticket.TTLContext
	}
	if err := saveJSON(ctx, s.rdb, keyPrefixContext+c.State, c, ttl); err != nil {
		return errs.Wrap(errs.CodeInternal, "保存授权上下文失败", err)
	}
	return nil
}

// ConsumeContext 原子取出并删除授权上下文。
//
// 一次性消费是防重放的关键：同一个 state 只能完成一次授权流程。
// 若用户刷新回调页面，第二次会得到 AUTH.INVALID_STATE，这是正确行为。
func (s *TicketStore) ConsumeContext(ctx context.Context, state string) (*ticket.Context, error) {
	if state == "" {
		return nil, ticket.ErrContextExpired
	}
	var c ticket.Context
	found, err := consumeAndDecode(ctx, s.rdb, keyPrefixContext+state, &c)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "读取授权上下文失败", err)
	}
	if !found {
		return nil, ticket.ErrContextExpired
	}
	return &c, nil
}

// SaveBindTicket 保存一次性绑定票据。
func (s *TicketStore) SaveBindTicket(ctx context.Context, t *ticket.BindTicket, ttl time.Duration) error {
	if t == nil || t.Ticket == "" {
		return errs.New(errs.CodeInternal, "绑定票据缺少 ticket")
	}
	if ttl <= 0 {
		ttl = ticket.TTLBindTicket
	}
	if err := saveJSON(ctx, s.rdb, keyPrefixBindTicket+t.Ticket, t, ttl); err != nil {
		return errs.Wrap(errs.CodeInternal, "保存绑定票据失败", err)
	}
	return nil
}

// ConsumeBindTicket 原子取出并删除绑定票据。
func (s *TicketStore) ConsumeBindTicket(ctx context.Context, ticketID string) (*ticket.BindTicket, error) {
	if ticketID == "" {
		return nil, ticket.ErrBindTicketInvalid
	}
	var t ticket.BindTicket
	found, err := consumeAndDecode(ctx, s.rdb, keyPrefixBindTicket+ticketID, &t)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "读取绑定票据失败", err)
	}
	if !found {
		return nil, ticket.ErrBindTicketInvalid
	}
	return &t, nil
}

// SaveAuthCode 保存一次性授权码。
func (s *TicketStore) SaveAuthCode(ctx context.Context, c *ticket.AuthCode, ttl time.Duration) error {
	if c == nil || c.Code == "" {
		return errs.New(errs.CodeInternal, "授权码缺少 code")
	}
	if ttl <= 0 {
		ttl = ticket.TTLAuthCode
	}
	if err := saveJSON(ctx, s.rdb, keyPrefixAuthCode+c.Code, c, ttl); err != nil {
		return errs.Wrap(errs.CodeInternal, "保存授权码失败", err)
	}
	return nil
}

// ConsumeAuthCode 原子取出并删除授权码。
func (s *TicketStore) ConsumeAuthCode(ctx context.Context, code string) (*ticket.AuthCode, error) {
	if code == "" {
		return nil, ticket.ErrAuthCodeInvalid
	}
	var c ticket.AuthCode
	found, err := consumeAndDecode(ctx, s.rdb, keyPrefixAuthCode+code, &c)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "读取授权码失败", err)
	}
	if !found {
		return nil, ticket.ErrAuthCodeInvalid
	}
	return &c, nil
}

// MarkReplay 记录已消费票据指纹，用于重放检测告警。
//
// 注意这里不是"拦截"而是"观测"：真正的防重放靠票据的一次性消费，
// 指纹表用于回答"有人在反复重放吗"，它的价值在告警与风控而非阻断面。
func (s *TicketStore) MarkReplay(ctx context.Context, fingerprint string, ttl time.Duration) error {
	if fingerprint == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if err := s.rdb.Set(ctx, keyPrefixReplay+fingerprint, time.Now().UTC().Unix(), ttl).Err(); err != nil {
		return errs.Wrap(errs.CodeInternal, "记录票据指纹失败", err)
	}
	return nil
}

// SeenReplay 判断指纹是否已出现过。
func (s *TicketStore) SeenReplay(ctx context.Context, fingerprint string) (bool, error) {
	if fingerprint == "" {
		return false, nil
	}
	n, err := s.rdb.Exists(ctx, keyPrefixReplay+fingerprint).Result()
	if err != nil {
		return false, errs.Wrap(errs.CodeInternal, "查询票据指纹失败", err)
	}
	return n > 0, nil
}

// SaveMergeTicket 保存待验证合并票据。
func (s *TicketStore) SaveMergeTicket(ctx context.Context, t *ticket.MergeTicket, ttl time.Duration) error {
	if t == nil || t.Ticket == "" {
		return errs.New(errs.CodeInternal, "合并票据缺少 ticket")
	}
	if ttl <= 0 {
		ttl = ticket.TTLMergeTicket
	}
	if err := saveJSON(ctx, s.rdb, keyPrefixMergeTicket+t.Ticket, t, ttl); err != nil {
		return errs.Wrap(errs.CodeInternal, "保存合并票据失败", err)
	}
	return nil
}

// GetMergeTicket 读取合并票据（不删除）。
//
// 刻意不提供"读即删"：用户要先发码再提交码，同一票据会被读两次。
// 一次性语义由"验证成功或次数耗尽时 Delete"保证——那才是真正的一次性边界。
func (s *TicketStore) GetMergeTicket(ctx context.Context, ticketID string) (*ticket.MergeTicket, error) {
	if ticketID == "" {
		return nil, ticket.ErrMergeTicketInvalid
	}
	var t ticket.MergeTicket
	found, err := getJSON(ctx, s.rdb, keyPrefixMergeTicket+ticketID, &t)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "读取合并票据失败", err)
	}
	if !found {
		return nil, ticket.ErrMergeTicketInvalid
	}
	return &t, nil
}

// DeleteMergeTicket 使合并票据失效。
func (s *TicketStore) DeleteMergeTicket(ctx context.Context, ticketID string) error {
	if ticketID == "" {
		return nil
	}
	if err := s.rdb.Del(ctx, keyPrefixMergeTicket+ticketID).Err(); err != nil {
		return errs.Wrap(errs.CodeInternal, "删除合并票据失败", err)
	}
	return nil
}
