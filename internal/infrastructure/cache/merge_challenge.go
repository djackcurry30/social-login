package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/djackcurry30/social-login/internal/domain/merge"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

const keyPrefixMergeChallenge = "merge:vcode:"

// MergeChallengeStore 是 merge.ChallengeStore 的 Redis 实现。
type MergeChallengeStore struct {
	rdb *redis.Client
}

// NewMergeChallengeStore 构造挑战存储。
func NewMergeChallengeStore(rdb *redis.Client) *MergeChallengeStore {
	return &MergeChallengeStore{rdb: rdb}
}

var _ merge.ChallengeStore = (*MergeChallengeStore)(nil)

// Save 保存挑战。
func (s *MergeChallengeStore) Save(ctx context.Context, c *merge.Challenge, ttl time.Duration) error {
	if c == nil || c.TicketID == "" {
		return errs.New(errs.CodeInternal, "验证码挑战缺少票据 ID")
	}
	if ttl <= 0 {
		ttl = merge.CodeTTL
	}
	if err := saveJSON(ctx, s.rdb, keyPrefixMergeChallenge+c.TicketID, c, ttl); err != nil {
		return errs.Wrap(errs.CodeInternal, "保存验证码挑战失败", err)
	}
	return nil
}

// Get 读取挑战。
func (s *MergeChallengeStore) Get(ctx context.Context, ticketID string) (*merge.Challenge, error) {
	if ticketID == "" {
		return nil, merge.ErrChallengeMissing
	}
	var c merge.Challenge
	found, err := getJSON(ctx, s.rdb, keyPrefixMergeChallenge+ticketID, &c)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "读取验证码挑战失败", err)
	}
	if !found {
		return nil, merge.ErrChallengeMissing
	}
	return &c, nil
}

// bumpScript 原子递增 attempts 并保留 TTL。
//
// 用 Lua 而不是 INCR + 单独字段：挑战是 JSON 存储，需要"读→改→写"，
// 而这中间有窗口。脚本里重新 SET 时保留原 PTTL，避免每次猜错都把
// 有效期续上（那等于给攻击者无限时间）。
var bumpScript = redis.NewScript(`
local raw = redis.call("get", KEYS[1])
if not raw then return -1 end
local obj = cjson.decode(raw)
obj["Attempts"] = (obj["Attempts"] or 0) + 1
local pttl = redis.call("pttl", KEYS[1])
if pttl <= 0 then pttl = 300000 end
redis.call("psetex", KEYS[1], pttl, cjson.encode(obj))
return obj["Attempts"]
`)

// BumpAttempt 原子累加尝试次数。
func (s *MergeChallengeStore) BumpAttempt(ctx context.Context, ticketID string) (int, error) {
	if ticketID == "" {
		return 0, merge.ErrChallengeMissing
	}
	n, err := bumpScript.Run(ctx, s.rdb, []string{keyPrefixMergeChallenge + ticketID}).Int()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, merge.ErrChallengeMissing
		}
		return 0, errs.Wrap(errs.CodeInternal, "累加验证码尝试次数失败", err)
	}
	if n < 0 {
		return 0, merge.ErrChallengeMissing
	}
	return n, nil
}

// Delete 删除挑战。
func (s *MergeChallengeStore) Delete(ctx context.Context, ticketID string) error {
	if ticketID == "" {
		return nil
	}
	if err := s.rdb.Del(ctx, keyPrefixMergeChallenge+ticketID).Err(); err != nil {
		return errs.Wrap(errs.CodeInternal, "删除验证码挑战失败", err)
	}
	return nil
}
