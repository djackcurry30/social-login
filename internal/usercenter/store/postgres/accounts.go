package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// ClaimInput 是一条待写入的凭证。
//
// 三个字段各司其职，缺一不可：
//   - ValueHash  查询用（等值匹配，唯一索引建在它上面）
//   - ValueCipher 展示与审计用（解密后才知道"这个号是多少"）
//   - Source     溯源用（"这个号是微信给的还是用户手填的"）
//
// ⚠️ 这里刻意【没有】明文值：明文不落库，只在 service 层内存里短暂存在。
// 连幂等快照也只存 user_id（见 CreateAccount 的注释）。
type ClaimInput struct {
	Type        string
	ValueHash   []byte
	HashVersion int16
	ValueCipher []byte
	DEKID       string
	Source      string
}

// CreateInput 是建号入参。
type CreateInput struct {
	AppID       int64
	AppKey      string
	IdemKey     string
	RequestHash []byte
	PublicID    string
	Nickname    string
	AvatarURL   string
	Claims      []ClaimInput
	// Audit 为 nil 表示不写审计（仅出现在单测与命令行工具里）。
	// 生产路径上由 service 构造：账号数据是合规对象，改动必须留痕。
	Audit *AuditInput
}

// CreateResult 是建号结果。
type CreateResult struct {
	AccountID int64
	PublicID  string
	Status    domain.Status
	CreatedAt time.Time
	// Replayed 为 true 表示命中了幂等键，本次没有新建账号。
	Replayed bool
}

// CreateAccount 建号（含幂等）。
//
// 幂等与建号在【同一个事务】里，这是刻意的：
//
//	把"占位"单独提交会引入两种新故障——进程在两步之间崩溃会留下永远
//	"处理中"的键（该用户的首次登录从此一直 409）；而占位单独提交后业务
//	事务回滚，键又会被错误地当成"已完成"。放在一个事务里，并发同键的
//	请求会在唯一索引上排队，先到者提交后后来者读到的必然是完整结果。
//
// ⚠️ 失败不缓存：凭证冲突会把整个事务回滚（含幂等占位）。下次同键重试会
// 重新尝试建号——这是对的，因为调用方此时通常会改走合并流程，而不是重放。
func (s *Store) CreateAccount(ctx context.Context, in CreateInput) (*CreateResult, error) {
	var out *CreateResult

	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// ① 幂等占位。ON CONFLICT DO NOTHING 而不是 DO UPDATE：
		//    命中的意思是"这个键已经被用过"，绝不能用新请求体覆盖旧结果。
		tag, err := tx.Exec(ctx, `
			INSERT INTO idempotency_keys (app_id, scope, key, request_hash, status_code, response)
			VALUES ($1, 'create_account', $2, $3, 0, '{}'::jsonb)
			ON CONFLICT (app_id, scope, key) DO NOTHING`,
			in.AppID, in.IdemKey, in.RequestHash)
		if err != nil {
			return translateDBError("insert_idempotency", err)
		}

		if tag.RowsAffected() == 0 {
			replayed, err := replayCreate(ctx, tx, in)
			if err != nil {
				return err
			}
			out = replayed
			return nil
		}

		// ② 建账号。
		var status string
		var createdAt time.Time
		var accountID int64
		err = tx.QueryRow(ctx, `
			INSERT INTO accounts (app_id, public_id, nickname, avatar_url)
			VALUES ($1, $2, $3, $4)
			RETURNING id, status, created_at`,
			in.AppID, in.PublicID, in.Nickname, in.AvatarURL).
			Scan(&accountID, &status, &createdAt)
		if err != nil {
			if isUniqueViolation(err, constraintAccountsPublic) {
				// ULID 撞车在 10 万级账号下概率约 0；真出现说明随机源有问题，
				// 不该自动重试掩盖它。
				return domain.New(domain.CodeInternal, "账号标识冲突（ULID 重复）").
					WithCause(err).WithDetail("public_id", in.PublicID)
			}
			return translateDBError("insert_account", err)
		}

		// ③ 写凭证。不先查后写：先查再插有 TOCTOU 窗口，
		//    两个并发同凭证建号会双双通过检查。让唯一索引当裁判。
		for _, c := range in.Claims {
			_, err := tx.Exec(ctx, `
				INSERT INTO account_claims
					(app_id, account_id, claim_type, value_hash, hash_version, value_cipher, dek_id, source)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				in.AppID, accountID, c.Type, c.ValueHash, c.HashVersion, c.ValueCipher, c.DEKID, c.Source)
			if err != nil {
				switch {
				case isUniqueViolation(err, constraintClaimValue):
					// 该凭证已被本应用内另一个账号持有。调用方据此走绑定冲突/合并。
					return domain.Newf(domain.CodeClaimTaken,
						"%s 凭证已被本应用内的其他账号占用", c.Type).
						WithDetail("claim_type", c.Type)
				case isUniqueViolation(err, constraintClaimOneType):
					// 同一请求里传了两条同类凭证。不是数据冲突，是请求不合法：
					// 一个账号每类只能有一条（§12.1 决策 2）。
					return domain.Newf(domain.CodeInvalid,
						"同一请求包含多条 %s 凭证：一个账号每类凭证只能有一条", c.Type)
				}
				return translateDBError("insert_claim", err)
			}
		}

		// ④ 回填幂等快照。
		//
		// 只存 user_id，不存完整账号报文：完整报文含凭证明文（或需要解密的密文），
		// 而幂等表是排障时会被直接 query 的地方，不该成为第二份敏感数据。
		// 重放时按 user_id 重新读当前状态——账号后来被合并/关闭也能如实反映。
		snapshot, _ := json.Marshal(map[string]string{"user_id": in.PublicID})
		if _, err := tx.Exec(ctx, `
			UPDATE idempotency_keys
			   SET status_code = 201, response = $1::jsonb
			 WHERE app_id = $2 AND scope = 'create_account' AND key = $3`,
			string(snapshot), in.AppID, in.IdemKey); err != nil {
			return translateDBError("update_idempotency", err)
		}

		// ⑤ 审计。放在同一事务的最后一步：前面任何一步失败都不会留下
		//    "建号成功但审计说没建"的错位记录。
		if in.Audit != nil {
			audit := *in.Audit
			audit.AccountID = accountID
			audit.UserID = in.PublicID
			if err := insertAudit(ctx, tx, &audit); err != nil {
				return err
			}
		}

		out = &CreateResult{
			AccountID: accountID,
			PublicID:  in.PublicID,
			Status:    domain.Status(status),
			CreatedAt: createdAt,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// replayCreate 处理幂等命中：校验请求体一致、返回原账号。
func replayCreate(ctx context.Context, tx pgx.Tx, in CreateInput) (*CreateResult, error) {
	var reqHash []byte
	var statusCode int
	var response []byte

	err := tx.QueryRow(ctx, `
		SELECT request_hash, status_code, response
		  FROM idempotency_keys
		 WHERE app_id = $1 AND scope = 'create_account' AND key = $2`,
		in.AppID, in.IdemKey).Scan(&reqHash, &statusCode, &response)
	if err != nil {
		return nil, translateDBError("load_idempotency", err)
	}

	// 同一个键被用于不同请求体：这是调用方的 bug（通常是幂等键生成逻辑写错，
	// 例如用了固定字符串）。返回旧结果等于"静默忽略了一次请求"，更危险。
	if string(reqHash) != string(in.RequestHash) {
		return nil, domain.New(domain.CodeInvalid,
			"同一 Idempotency-Key 被用于了不同的请求体，拒绝复用")
	}
	if statusCode == 0 {
		// 单事务实现下不应观察到：占位行只有提交后才对其他事务可见，
		// 而提交时它已经被回填。保留这个分支是为了兼容将来改成两段式提交。
		return nil, domain.New(domain.CodeIdemInProgress, "同一幂等键的请求仍在处理中")
	}

	var ref struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(response, &ref); err != nil || ref.UserID == "" {
		return nil, domain.New(domain.CodeInternal, "幂等快照损坏（缺少 user_id）").
			WithCause(err)
	}

	// 重新读当前状态：首次建号之后账号可能已被合并（closed）。
	// 直接返回 201 时的 active 会让调用方以为账号仍然可用。
	var id int64
	var status string
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, status, created_at FROM accounts WHERE app_id = $1 AND public_id = $2`,
		in.AppID, ref.UserID).Scan(&id, &status, &createdAt)
	if err != nil {
		return nil, translateDBError("reload_replayed_account", err)
	}

	return &CreateResult{
		AccountID: id,
		PublicID:  ref.UserID,
		Status:    domain.Status(status),
		CreatedAt: createdAt,
		Replayed:  true,
	}, nil
}

// Snapshot 是账号读取结果：账号行 + 活跃凭证行（密文未解密）。
type Snapshot struct {
	Account domain.Account
	Claims  []domain.ClaimRecord
}

// accountSelect 是账号读取的公共列。
//
// merged_into 用 LEFT JOIN 换出 public_id：调用方要知道"这个 id 去哪了"，
// 而内部自增 id 对它没有意义。
const accountSelect = `
	SELECT a.id, a.public_id, a.status, a.nickname, a.avatar_url,
	       a.created_at, a.updated_at, COALESCE(m.public_id, '')
	  FROM accounts a
	  LEFT JOIN accounts m ON m.id = a.merged_into`

// GetAccount 按 public_id 查账号。
//
// 跨应用一律 ACCOUNT.NOT_FOUND（不泄漏存在性）：同一个 public_id 在
// 另一个应用下是否存在，是别的租户的信息。
func (s *Store) GetAccount(ctx context.Context, appID int64, publicID string) (*Snapshot, error) {
	row := s.pool.QueryRow(ctx, accountSelect+` WHERE a.app_id = $1 AND a.public_id = $2`, appID, publicID)

	snap := &Snapshot{}
	var mergedInto string
	err := row.Scan(&snap.Account.ID, &snap.Account.UserID, &snap.Account.Status,
		&snap.Account.Nickname, &snap.Account.AvatarURL,
		&snap.Account.CreatedAt, &snap.Account.UpdatedAt, &mergedInto)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.New(domain.CodeNotFound, "账号不存在")
		}
		return nil, translateDBError("get_account", err)
	}
	snap.Account.MergedInto = mergedInto

	// 内部自增 id 不放进 domain.Account（那是对外视图），这里单独带出去。
	return s.withClaims(ctx, appID, snap)
}

// withClaims 读取账号的活跃凭证。
//
// 只读活跃行（revoked_at IS NULL）：契约里的 claims 是"当前持有的凭证"，
// 历史行是审计材料，混进来会让调用方以为账号还绑着旧号。
func (s *Store) withClaims(ctx context.Context, appID int64, snap *Snapshot) (*Snapshot, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, account_id, claim_type, value_hash, hash_version, value_cipher,
		       dek_id, source, verified_at
		  FROM account_claims
		 WHERE app_id = $1 AND account_id = $2 AND revoked_at IS NULL
		 ORDER BY claim_type`, appID, snap.Account.ID)
	if err != nil {
		return nil, translateDBError("list_claims", err)
	}
	defer rows.Close()

	for rows.Next() {
		var c domain.ClaimRecord
		if err := rows.Scan(&c.ID, &c.AccountID, &c.Type, &c.ValueHash, &c.HashVersion,
			&c.ValueCipher, &c.DEKID, &c.Source, &c.VerifiedAt); err != nil {
			return nil, translateDBError("scan_claim", err)
		}
		snap.Claims = append(snap.Claims, c)
	}
	if err := rows.Err(); err != nil {
		return nil, translateDBError("iterate_claims", err)
	}
	return snap, nil
}

// FindByClaim 按凭证反查账号。
//
// ⚠️ 必须强一致读：这是 social-login 归并前的最后一道防线（P0-6）。
// 读到延迟从库的旧数据会让防线失效——它会把一个刚换了手机号的账号
// 判定为"没有归属"，进而把错误的人并进来。所以本服务的连接池里
// 根本没有从库配置，连"误配"的可能性都不提供。
func (s *Store) FindByClaim(ctx context.Context, appID int64, claimType string, valueHash []byte) (*Snapshot, error) {
	// LIMIT 2 而不是 1：唯一索引理论上最多一条，但"理论上"不足以让人放心。
	// 真出现两条时，宁可报 MULTIPLE 让调用方走人工排查，也不要随手挑一个。
	rows, err := s.pool.Query(ctx, `
		SELECT a.public_id
		  FROM account_claims c
		  JOIN accounts a ON a.id = c.account_id AND a.app_id = c.app_id
		 WHERE c.app_id = $1 AND c.claim_type = $2 AND c.value_hash = $3
		   AND c.revoked_at IS NULL
		 LIMIT 2`, appID, claimType, valueHash)
	if err != nil {
		return nil, translateDBError("find_by_claim", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, translateDBError("scan_by_claim", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, translateDBError("iterate_by_claim", err)
	}

	switch len(ids) {
	case 0:
		return nil, domain.New(domain.CodeNotFound, "没有账号持有该凭证")
	case 1:
		return s.GetAccount(ctx, appID, ids[0])
	default:
		// 数据已经不满足唯一性。调用方（social-login）会转成人工排查，
		// 而不是择一合并——择一合并正是把错误账号并进来的那条路。
		return nil, domain.Newf(domain.CodeMultiple,
			"该凭证对应了 %d 个账号，用户中心唯一性已损坏，需要人工处理", len(ids))
	}
}
