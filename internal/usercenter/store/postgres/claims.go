package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// ReplaceClaim 原子替换某账号某类型的凭证。
//
// 为什么必须有这个接口：唯一索引只定义了"不能并存"，没定义"怎么换"。
// 没有它，纠正一个手机号只能靠合并——而合并会把整个 source 账号关掉，
// 为了改个号码牺牲一个账号，显然不对（§5.4）。
//
// 并发语义是【乐观】的，不加 FOR UPDATE：
//
//	两个换绑同时来，各自读到同一个旧凭证 id，然后都执行
//	UPDATE ... WHERE id=$old AND revoked_at IS NULL。
//	PostgreSQL 的行锁会让后到者等待，提交后重新求值谓词——
//	此时 revoked_at 已非空，影响 0 行，于是它拿到 ACCOUNT.CONFLICT。
//
//	如果这里加了 FOR UPDATE，后到者会等第一个提交、然后看到【新】凭证并把
//	它撤销，最后两个请求都返回 200（last-write-wins）。用户看到"换成了 A"，
//	实际生效的是 B——这种静默覆盖比报错危险得多。
func (s *Store) ReplaceClaim(ctx context.Context, appID int64, publicID string, in ClaimInput,
	audit *AuditInput, notify *OutboxInput,
) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		// ① 定位账号。已关闭的账号不允许换绑：它的凭证应当已经全部撤销，
		//    再插一条会让"已注销"的账号重新出现在 by-claim 的结果里。
		var accountID int64
		var status string
		err := tx.QueryRow(ctx,
			`SELECT id, status FROM accounts WHERE app_id = $1 AND public_id = $2`,
			appID, publicID).Scan(&accountID, &status)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.New(domain.CodeNotFound, "账号不存在")
			}
			return translateDBError("replace_get_account", err)
		}
		if status == string(domain.StatusClosed) {
			return domain.New(domain.CodeNotFound, "账号已关闭，不能换绑凭证")
		}

		// ② 新值已经属于本账号同类 → 幂等 no-op（重复调用不报错）。
		var owner int64
		err = tx.QueryRow(ctx, `
			SELECT account_id FROM account_claims
			 WHERE app_id = $1 AND claim_type = $2 AND value_hash = $3 AND revoked_at IS NULL`,
			appID, in.Type, in.ValueHash).Scan(&owner)
		switch {
		case err == nil && owner == accountID:
			return nil
		case err == nil:
			// 被其他账号持有。这里提前查是为了给出准确错误码：
			// 若靠插入时的唯一冲突兜底，同样会得到 CLAIM_TAKEN，
			// 但"这条号是谁的"就查不了了（事务已中止）。
			return domain.Newf(domain.CodeClaimTaken,
				"%s 凭证已被本应用内的其他账号占用", in.Type)
		case !errors.Is(err, pgx.ErrNoRows):
			return translateDBError("replace_check_new_value", err)
		}

		// ③ 找到本账号该类型的当前凭证。没有则是首次绑定，直接插。
		var oldID int64
		var oldHash []byte
		err = tx.QueryRow(ctx, `
			SELECT id, value_hash FROM account_claims
			 WHERE app_id = $1 AND account_id = $2 AND claim_type = $3 AND revoked_at IS NULL`,
			appID, accountID, in.Type).Scan(&oldID, &oldHash)
		hasOld := true
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return translateDBError("replace_get_old", err)
			}
			hasOld = false
		}

		if hasOld {
			// ④ 条件撤销。影响 0 行 = 被并发改掉了。
			tag, err := tx.Exec(ctx, `
				UPDATE account_claims
				   SET revoked_at = now(), revoke_reason = 'replaced'
				 WHERE id = $1 AND revoked_at IS NULL`, oldID)
			if err != nil {
				return translateDBError("replace_revoke_old", err)
			}
			if tag.RowsAffected() == 0 {
				return domain.New(domain.CodeConflict, "该凭证已被并发修改，请重试")
			}
		}

		// ⑤ 插入新凭证。
		_, err = tx.Exec(ctx, `
			INSERT INTO account_claims
				(app_id, account_id, claim_type, value_hash, hash_version, value_cipher, dek_id, source)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			appID, accountID, in.Type, in.ValueHash, in.HashVersion, in.ValueCipher, in.DEKID, in.Source)
		if err != nil {
			switch {
			case isUniqueViolation(err, constraintClaimValue):
				return domain.Newf(domain.CodeClaimTaken,
					"%s 凭证已被本应用内的其他账号占用", in.Type)
			case isUniqueViolation(err, constraintClaimOneType):
				// 首次绑定分支下的并发：两个请求都以为账号没有该类凭证。
				return domain.New(domain.CodeConflict, "并发换绑冲突，请重试")
			}
			return translateDBError("replace_insert", err)
		}

		// 审计动作由这里判定：只有 store 知道这次是首次绑定还是换绑。
		// 写成同一个动作（claim.replaced）会让"用户第一次绑手机号"看起来像
		// 换过一次号，客服据此回答"你换过号码"就是错的。
		if audit != nil {
			a := *audit
			if hasOld {
				a.Action = AuditClaimReplaced
			} else {
				a.Action = AuditClaimBound
			}
			a.AccountID = accountID
			a.UserID = publicID
			if a.Detail == nil {
				a.Detail = map[string]any{}
			}
			a.Detail["claim_type"] = in.Type
			a.Detail["source"] = in.Source
			if err := insertAudit(ctx, tx, &a); err != nil {
				return err
			}
		}
		if err := insertOutbox(ctx, tx, notify); err != nil {
			return err
		}
		return nil
	})
}

// CloseAccount 关闭账号并撤销全部凭证。
//
// MVP 只做这一个原子动作（§11）：完整的注销流程要联动 social-login 的绑定、
// 令牌、事件与业务方通知，做半套比不做更危险——用户以为注销了，
// 另一侧还留着数据。所以这里只保证"UC 这一侧干净且不可逆"。
//
// 幂等：已关闭账号再次注销返回 nil，不报错。注销是用户可能重复点击的操作，
// 第二次报"账号不存在"会让前端弹出莫名其妙的错误。
func (s *Store) CloseAccount(ctx context.Context, appID int64, publicID string,
	audit *AuditInput, notify *OutboxInput,
) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var accountID int64
		var status string
		err := tx.QueryRow(ctx,
			`SELECT id, status FROM accounts WHERE app_id = $1 AND public_id = $2`,
			appID, publicID).Scan(&accountID, &status)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.New(domain.CodeNotFound, "账号不存在")
			}
			return translateDBError("close_get_account", err)
		}
		if status == string(domain.StatusClosed) {
			return nil
		}

		// 先撤销凭证再关账号：反过来的话，若撤销失败，账号已是 closed 而凭证
		// 仍然活跃，by-claim 会查到一个"已注销但还绑着手机号"的账号。
		revoked, err := revokeRemaining(ctx, tx, appID, accountID, "closed")
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE accounts SET status = 'closed', updated_at = now()
			 WHERE app_id = $1 AND id = $2 AND status <> 'closed'`,
			appID, accountID); err != nil {
			return translateDBError("close_account", err)
		}

		// 审计：记账撤销了几条凭证。合规问"注销后还剩什么"时，这是唯一依据。
		if audit != nil {
			a := *audit
			a.AccountID = accountID
			a.UserID = publicID
			if a.Detail == nil {
				a.Detail = map[string]any{}
			}
			a.Detail["claims_revoked"] = len(revoked)
			if err := insertAudit(ctx, tx, &a); err != nil {
				return err
			}
		}
		// 出站事件与审计同理：注销会释放全部凭证，登录侧必须立刻失效本地 claim，
		// 否则它还会用"这个人拥有这个手机号"做归并判定。
		if err := insertOutbox(ctx, tx, notify); err != nil {
			return err
		}
		return nil
	})
}

// CountAccounts 返回某应用的账号数（运维端点用）。
func (s *Store) CountAccounts(ctx context.Context, appID int64) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM accounts WHERE app_id = $1`, appID).Scan(&n)
	if err != nil {
		return 0, translateDBError("count_accounts", err)
	}
	return n, nil
}
