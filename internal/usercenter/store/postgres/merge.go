package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// MergeInput 是合并入参。
type MergeInput struct {
	AppID          int64
	IdemKey        string
	TargetPublicID string
	SourcePublicID string
	Reason         string
	// Audit 为 nil 表示不写审计；生产路径由 service 构造。
	// 重放（已合并）不写审计：本次没有改变任何数据。
	Audit *AuditInput
	// Notify 是给登录侧的出站事件（source 账号已被关掉）。
	// 与审计同事务写入；重放路径不会走到这里（那里直接 return）。
	Notify *OutboxInput
}

// MergeResult 是合并结果。
//
// Merged 与 AlreadyMerged 的组合语义（契约里写死，踩过一次坑）：
//
//	{merged:true,  already_merged:false} 本次真的合并了
//	{merged:false, already_merged:true}  本次没有合并（之前已合并过）
//
// 绝不能把首次结果原样返回给重放请求：补偿任务据此判断"还要不要再推进本地收敛"，
// 返回 merged:true 会让它以为又合并了一次，进而重复迁移（§5.2 第 1 条）。
type MergeResult struct {
	Merged         bool
	AlreadyMerged  bool
	TargetPublicID string
	SourcePublicID string
	// Discarded 是因"目标已有同类型凭证"而被撤销的 source 凭证（尚未解密）。
	Discarded []domain.ClaimRecord
}

// MergeAccounts 把 source 合并进 target。
//
// 整个过程是一笔本地事务，包含六步（§5.2）：幂等检查 → 按 id 升序加锁 →
// 校验 → 迁移凭证 → 撤销剩余 → 关闭 source。
//
// 三个关键决定：
//
//  1. 【按 id 升序加锁】。A→B 与 B→A 并发时，若各自按自己的顺序锁，
//     就会互相等对方持有的行，形成死锁。统一顺序后，后到的那个只会等待，
//     拿到锁时 source 已 closed，返回 already_merged。
//
//  2. 【凭证按类型目标优先】。target 已有该类凭证（哪怕号不同）时，
//     source 的这条只能撤销、不能迁移——因为唯一索引
//     uk_claim_one_per_type 不允许一个账号挂两个手机号。
//     被撤销的凭证会回传给调用方（discarded_claims），
//     否则用户会问"我另一个号呢"，客服查不出原因（§5.2 第 4 条）。
//
//  3. 【只记成功的合并】。被拒绝的合并（同 id、跨应用、source 已关闭）
//     没有副作用，重放时重新判定即可；写进 merges 会让重放返回
//     already_merged=true，而那次调用并没有合并任何东西。
func (s *Store) MergeAccounts(ctx context.Context, in MergeInput) (*MergeResult, error) {
	if in.TargetPublicID == in.SourcePublicID {
		// 放在事务外：这不是并发问题，是参数错误，没必要占一把锁。
		return nil, domain.New(domain.CodeMergeRejected, "target 与 source 是同一个账号")
	}

	var out *MergeResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// ① 幂等命中：同一笔合并重放，直接返回"本次未合并"。
		if prev, err := loadMergeByIdemKey(ctx, tx, in.AppID, in.IdemKey); err != nil {
			return err
		} else if prev != nil {
			out = prev
			return nil
		}

		// ② 按 id 升序加锁，防双向死锁。
		type locked struct {
			id       int64
			publicID string
			status   string
			mergedTo *int64
		}
		rows, err := tx.Query(ctx, `
			SELECT id, public_id, status, merged_into
			  FROM accounts
			 WHERE app_id = $1 AND public_id = ANY($2::text[])
			 ORDER BY id
			 FOR UPDATE`,
			in.AppID, []string{in.TargetPublicID, in.SourcePublicID})
		if err != nil {
			return translateDBError("lock_accounts", err)
		}
		var found []locked
		for rows.Next() {
			var l locked
			if err := rows.Scan(&l.id, &l.publicID, &l.status, &l.mergedTo); err != nil {
				rows.Close()
				return translateDBError("scan_locked", err)
			}
			found = append(found, l)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return translateDBError("iterate_locked", err)
		}

		var target, source *locked
		for i := range found {
			switch found[i].publicID {
			case in.TargetPublicID:
				target = &found[i]
			case in.SourcePublicID:
				source = &found[i]
			}
		}

		// ③ 校验。跨应用/不存在都按 404：调用方无从试探另一个租户里有没有这个人。
		//    （查询本身已经带 app_id，所以"另一个应用的账号"天然查不到。）
		if target == nil {
			return domain.New(domain.CodeNotFound, "target 账号不存在于本应用")
		}
		if source == nil {
			return domain.New(domain.CodeNotFound, "source 账号不存在于本应用")
		}
		if target.status == string(domain.StatusClosed) {
			// 合并进一个已关闭的账号 = 数据进了黑洞：source 被关掉、
			// 凭证迁过去也没有任何人能读到。
			return domain.New(domain.CodeMergeRejected, "target 账号已关闭，不能作为合并目标")
		}
		if source.status == string(domain.StatusClosed) {
			// 已被合并过（可能用了另一个幂等键）。指向同一个 target 才叫"已完成"，
			// 指向别人说明调用方拿了一个过期的 source。
			if source.mergedTo != nil && *source.mergedTo == target.id {
				out = &MergeResult{
					Merged:         false,
					AlreadyMerged:  true,
					TargetPublicID: target.publicID,
					SourcePublicID: source.publicID,
				}
				return nil
			}
			return domain.New(domain.CodeMergeRejected, "source 账号已关闭，无法再次合并")
		}

		// ④ 迁移凭证：source 有、target 没有该类型的，改挂到 target。
		//
		// 不会撞 uk_claim_value：source 持有的凭证值在迁移前只属于 source
		// （唯一索引保证），target 此前没有同值凭证。可能撞的是
		// uk_claim_one_per_type——只在并发给 target 加同类凭证时发生，
		// 属于可重试冲突。
		if _, err := tx.Exec(ctx, `
			UPDATE account_claims c
			   SET account_id = $3
			 WHERE c.app_id = $1
			   AND c.account_id = $2
			   AND c.revoked_at IS NULL
			   AND NOT EXISTS (
			       SELECT 1 FROM account_claims t
			        WHERE t.app_id = c.app_id
			          AND t.account_id = $3
			          AND t.claim_type = c.claim_type
			          AND t.revoked_at IS NULL)`,
			in.AppID, source.id, target.id); err != nil {
			if isUniqueViolation(err, constraintClaimOneType) {
				return domain.New(domain.CodeConflict,
					"合并期间目标账号新增了同类凭证，请重试")
			}
			return translateDBError("move_claims", err)
		}

		// ⑤ 撤销 source 剩下的活跃凭证（即因目标已有同类型而放弃的那些）。
		discarded, err := revokeRemaining(ctx, tx, in.AppID, source.id, "merged_source")
		if err != nil {
			return err
		}

		// ⑥ 关闭 source 并指向 target。
		//
		// 不删除 source：public_id 已经发给业务方（写进对方的用户表），
		// 删掉会让历史数据指向空气；置 closed 后还能回答"这个 id 去哪了"。
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			   SET status = 'closed', merged_into = $3, updated_at = now()
			 WHERE app_id = $1 AND id = $2 AND status <> 'closed'`,
			in.AppID, source.id, target.id); err != nil {
			return translateDBError("close_source", err)
		}

		// ⑦ 记流水。并发同键在这里会被唯一约束挡住，按"已完成"处理。
		_, err = tx.Exec(ctx, `
			INSERT INTO merges (app_id, idem_key, target_id, source_id, reason)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (app_id, idem_key) DO NOTHING`,
			in.AppID, in.IdemKey, target.id, source.id, in.Reason)
		if err != nil {
			return translateDBError("insert_merge", err)
		}

		out = &MergeResult{
			Merged:         true,
			TargetPublicID: target.publicID,
			SourcePublicID: source.publicID,
			Discarded:      discarded,
		}

		// ⑧ 审计。source 与 target 都记：只记 target 会丢掉
		//    "哪个账号被并走了"——而这正是客服最常被问到的问题。
		if in.Audit != nil {
			a := *in.Audit
			a.AccountID = target.id
			a.UserID = target.publicID
			if a.Detail == nil {
				a.Detail = map[string]any{}
			}
			a.Detail["source_user_id"] = source.publicID
			a.Detail["source_account_id"] = source.id
			a.Detail["discarded_claims"] = len(discarded)
			if in.Reason != "" {
				a.Detail["reason"] = in.Reason
			}
			if err := insertAudit(ctx, tx, &a); err != nil {
				return err
			}
		}
		if err := insertOutbox(ctx, tx, in.Notify); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// loadMergeByIdemKey 按幂等键读已完成的合并，没有则返回 nil。
func loadMergeByIdemKey(ctx context.Context, tx pgx.Tx, appID int64, idemKey string) (*MergeResult, error) {
	const q = `
		SELECT t.public_id, s.public_id
		  FROM merges m
		  JOIN accounts t ON t.id = m.target_id
		  JOIN accounts s ON s.id = m.source_id
		 WHERE m.app_id = $1 AND m.idem_key = $2`

	var target, source string
	err := tx.QueryRow(ctx, q, appID, idemKey).Scan(&target, &source)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, translateDBError("load_merge", err)
	}
	// 不返回 discarded：这次调用没有丢弃任何东西。
	return &MergeResult{
		Merged:         false,
		AlreadyMerged:  true,
		TargetPublicID: target,
		SourcePublicID: source,
	}, nil
}

// revokeRemaining 撤销某账号在当前事务内仍活跃的凭证，返回被撤销的行。
func revokeRemaining(ctx context.Context, tx pgx.Tx, appID, accountID int64, reason string) ([]domain.ClaimRecord, error) {
	rows, err := tx.Query(ctx, `
		UPDATE account_claims
		   SET revoked_at = now(), revoke_reason = $3
		 WHERE app_id = $1 AND account_id = $2 AND revoked_at IS NULL
		 RETURNING id, account_id, claim_type, value_hash, hash_version,
		           value_cipher, dek_id, source, verified_at, revoked_at`,
		appID, accountID, reason)
	if err != nil {
		return nil, translateDBError("revoke_claims", err)
	}
	defer rows.Close()

	var out []domain.ClaimRecord
	for rows.Next() {
		var c domain.ClaimRecord
		if err := rows.Scan(&c.ID, &c.AccountID, &c.Type, &c.ValueHash, &c.HashVersion,
			&c.ValueCipher, &c.DEKID, &c.Source, &c.VerifiedAt, &c.RevokedAt); err != nil {
			return nil, translateDBError("scan_revoked", err)
		}
		c.RevokeReason = reason
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, translateDBError("iterate_revoked", err)
	}
	return out, nil
}
