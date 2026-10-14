package postgres

import (
	"fmt"
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/17track/social-login/internal/pkg/appctx"
)

// scopedTables 是需要强制应用隔离的表（约束 C1）。
//
// 判定口径：表里有 app_id 列，且其中的数据天然属于某个业务应用。
// 【不包含】applications（它本身就是应用表）与 admin_*（管理端天然跨应用）。
var scopedTables = map[string]bool{
	"app_provider_configs": true,
	"oauth_identities":     true,
	"identity_claims":      true,
	"oauth_bindings":       true,
	"refresh_tokens":       true,
	"merge_operations":     true,
	"event_outbox":         true,
	"auth_audit_logs":      true,
}

// 回调名称。
const (
	cbNameQuery  = "social_login:app_scope:query"
	cbNameUpdate = "social_login:app_scope:update"
	cbNameDelete = "social_login:app_scope:delete"
	cbNameCreate = "social_login:app_scope:create"
)

// registerAppScopeCallbacks 注册全局隔离回调。
//
// 为什么用 GORM 全局 Callback 而不是靠 code review 保证：
// 架构 §9.1 要求"所有查询路径都必须带 app_id"。手写 SQL 时代这只能靠人工检查，
// 漏一处就是一次线上串号事故。放到 Callback 里则是【机制强制】——漏写会被自动
// 补上；而如果连作用域都没建立，直接 panic，让问题在开发/测试阶段就炸出来。
//
// 这也是放弃 pgx + sqlc 那套方案的主要原因。
func registerAppScopeCallbacks(db *gorm.DB) error {
	// 查询：注入 app_id 条件。放在 gorm:query 之前，使其参与 SQL 构建。
	if err := db.Callback().Query().Before("gorm:query").
		Register(cbNameQuery, func(tx *gorm.DB) { injectAppScopeCondition(tx, "查询") }); err != nil {
		return fmt.Errorf("注册查询隔离回调失败: %w", err)
	}

	// 更新 / 删除：同样注入条件。
	//
	// 注意注册顺序：GORM 内置的 checkMissingWhereConditions 注册在 gorm:update /
	// gorm:delete 之前、且早于本回调，因此"完全没有 WHERE 的全局更新/删除"
	// 仍然会被内置守卫拦下（返回 ErrMissingWhereClause）——这是期望行为，
	// 我们注入的 app_id 不应成为"顺手解除全局写保护"的借口。
	if err := db.Callback().Update().Before("gorm:update").
		Register(cbNameUpdate, func(tx *gorm.DB) { injectAppScopeCondition(tx, "更新") }); err != nil {
		return fmt.Errorf("注册更新隔离回调失败: %w", err)
	}
	if err := db.Callback().Delete().Before("gorm:delete").
		Register(cbNameDelete, func(tx *gorm.DB) { injectAppScopeCondition(tx, "删除") }); err != nil {
		return fmt.Errorf("注册删除隔离回调失败: %w", err)
	}

	// 创建：校验并补全模型上的 app_id。
	//
	// 创建无法用"加 WHERE"解决，改为直接操作待写入的记录：缺失则用作用域补上，
	// 不一致则 panic——后者说明调用方显式写错了应用，静默改写会掩盖 bug。
	if err := db.Callback().Create().Before("gorm:create").
		Register(cbNameCreate, func(tx *gorm.DB) { enforceCreateScope(tx) }); err != nil {
		return fmt.Errorf("注册创建隔离回调失败: %w", err)
	}
	return nil
}

// injectAppScopeCondition 为 SQL 注入 app_id 条件。
func injectAppScopeCondition(tx *gorm.DB, op string) {
	stmt := tx.Statement
	if stmt == nil {
		return
	}
	table := tableOf(stmt)
	if !scopedTables[table] {
		return
	}
	scope, ok := appctx.From(stmt.Context)
	if !ok {
		panic(isolationPanicMsg(table, op))
	}
	if scope.CrossApp {
		// 管理端显式跨应用：不加条件，但这是代码里可见的一次显式声明。
		return
	}
	stmt.AddClause(clause.Where{
		Exprs: []clause.Expression{
			clause.Eq{
				Column: clause.Column{Table: clause.CurrentTable, Name: "app_id"},
				Value:  scope.AppID,
			},
		},
	})
}

// enforceCreateScope 校验并补全待写入记录的 app_id。
func enforceCreateScope(tx *gorm.DB) {
	stmt := tx.Statement
	if stmt == nil {
		return
	}
	table := tableOf(stmt)
	if !scopedTables[table] {
		return
	}
	scope, ok := appctx.From(stmt.Context)
	if !ok {
		panic(isolationPanicMsg(table, "写入"))
	}
	if scope.CrossApp {
		return
	}
	applyAppID(stmt.ReflectValue, scope.AppID, table)
}

// applyAppID 递归处理待写入的值（结构体或结构体切片），补全/校验 AppID 字段。
func applyAppID(v reflect.Value, appID int64, table string) {
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			applyAppID(v.Index(i), appID, table)
		}
	case reflect.Ptr:
		if !v.IsNil() {
			applyAppID(v.Elem(), appID, table)
		}
	case reflect.Struct:
		f := v.FieldByName("AppID")
		if !f.IsValid() || !f.CanSet() || f.Kind() != reflect.Int64 {
			// 模型没有 AppID 字段却落在 scopedTables 里，说明 scopedTables
			// 与模型定义已经不一致——这是需要修代码的信号，不能默默放过。
			panic(fmt.Sprintf(
				"app_id 隔离配置不一致：表 %s 在 scopedTables 中被声明为按应用隔离，"+
					"但模型 %s 没有可写的 AppID 字段。请同步修改 internal/infrastructure/persistence/postgres/scope.go",
				table, v.Type().String()))
		}
		if f.Int() == 0 {
			f.SetInt(appID)
			return
		}
		if f.Int() != appID {
			panic(fmt.Sprintf(
				"app_id 隔离冲突：准备写入表 %s 的记录 app_id=%d，但当前应用上下文为 app_id=%d。"+
					"如果这是有意的跨应用写入，请显式使用 appctx.WithCrossAppScope(ctx)（仅管理端）",
				table, f.Int(), appID))
		}
	}
}

// tableOf 尽力解析语句操作的表名。
//
// 优先用 Statement.Schema（常规 Model/Dest 路径）；退化到 Statement.Table
// （db.Table("x") 这类显式指定表名的用法），避免留下绕过隔离的口子。
func tableOf(stmt *gorm.Statement) string {
	if stmt.Schema != nil && stmt.Schema.Table != "" {
		return stmt.Schema.Table
	}
	return stmt.Table
}

func isolationPanicMsg(table, op string) string {
	return fmt.Sprintf(
		"app_id 隔离缺失：对表 %s 执行%s操作时未提供应用上下文（架构 §9.1）。"+
			"业务端请用 appctx.WithAppScope(ctx, appID)；管理端跨应用访问请用 appctx.WithCrossAppScope(ctx)",
		table, op)
}
