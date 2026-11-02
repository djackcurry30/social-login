package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// RegisterApp 幂等注册/更新一个应用。
//
// 为什么是 upsert 而不是"存在即报错"：对账任务每 5 分钟把全部应用重放一遍（§2.6），
// 不幂等的实现会不断造出重复租户，而重复租户的表现是"用户被随机分到其中一份，
// 另一半数据永远查不到"。
//
// 为什么 name/status 总是覆盖：这两个字段的唯一真相源在 social-login 的管理端。
// UC 侧保留旧值没有意义——它自己不会改这两个字段，只可能没跟上。
func (s *Store) RegisterApp(ctx context.Context, appKey, name string, status int16) (domain.App, error) {
	const q = `
		INSERT INTO apps (app_key, name, status)
		VALUES ($1, $2, $3)
		ON CONFLICT (app_key) DO UPDATE
		   SET name = EXCLUDED.name,
		       status = EXCLUDED.status,
		       updated_at = now()
		RETURNING id, app_key, name, status`

	var app domain.App
	err := s.pool.QueryRow(ctx, q, appKey, name, status).
		Scan(&app.ID, &app.Key, &app.Name, &app.Status)
	if err != nil {
		return domain.App{}, translateDBError("register_app", err)
	}
	return app, nil
}

// FindApp 按 app_key 查应用。不存在返回 ACCOUNT 域之外的 APP.UNKNOWN。
//
// 每次请求都查库，不做进程内缓存：
//   - 这是唯一索引上的单行查询，p99 在亚毫秒级，5 应用 × 10 万账号的量级下
//     完全不是瓶颈；
//   - 缓存会引入"停用应用后仍能登录若干秒"的窗口，也会引入缓存一致性代码。
//     本服务不做的功能（如登录态）远比多一次查询值钱。
func (s *Store) FindApp(ctx context.Context, appKey string) (domain.App, error) {
	const q = `SELECT id, app_key, name, status FROM apps WHERE app_key = $1`

	var app domain.App
	err := s.pool.QueryRow(ctx, q, appKey).Scan(&app.ID, &app.Key, &app.Name, &app.Status)
	if err != nil {
		if err == pgx.ErrNoRows {
			// 不做懒注册：配置里写错一个字母（app_web_porta1）就会静默造出一个
			// 空租户，该应用所有用户都变成"新用户"并触发建号。
			// 这种错误不报错，只表现成"用户数据全丢了"（§2.6）。
			return domain.App{}, domain.Newf(domain.CodeAppUnknown, "应用未在用户中心注册: %s", appKey)
		}
		return domain.App{}, translateDBError("find_app", err)
	}
	return app, nil
}

// CountApps 返回已注册应用数量（运维端点用）。
func (s *Store) CountApps(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM apps`).Scan(&n)
	if err != nil {
		return 0, translateDBError("count_apps", err)
	}
	return n, nil
}
