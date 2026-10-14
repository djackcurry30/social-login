package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// PostgreSQL 错误码（SQLSTATE），只列出本项目需要精确捕获的几个。
const (
	pgCodeUniqueViolation     = "23505"
	pgCodeForeignKeyViolation = "23503"
	pgCodeNotNullViolation    = "23502"
	pgCodeCheckViolation      = "23514"
)

// IsUniqueViolation 判断是否为唯一约束冲突。
//
// 这是本项目最重要的一个错误判定：部分唯一索引 uk_claims_verified 与
// uk_bindings_active 的冲突【是正常业务信号】而不是系统错误——
// 它意味着"该凭证已被另一个身份验证过"或"该身份已被占用"，
// 调用方据此走冲突/合并流程（架构 §5.2 的并发绑定安全设计）。
//
// 之所以要精确捕获而不是笼统判断 err != nil：一旦把冲突当成系统错误，
// 就会出现"两个人同时绑同一个微信，后一个报 500"这种线上事故。
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pgCodeUniqueViolation
	}
	return false
}

// IsForeignKeyViolation 判断是否为外键约束冲突。
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pgCodeForeignKeyViolation
	}
	return false
}

// ConstraintName 在可能的情况下返回被违反的约束名，用于日志与排障。
func ConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
