// Package migrations 把 SQL 迁移文件嵌入二进制。
//
// 嵌入而不是运行时读目录，是为了让"代码 + schema"作为一个不可分割的发布单元：
// 部署时漏拷 migrations 目录会导致服务启动即失败，而这本可以在编译期避免。
//
// 迁移文件的【唯一真相源】就是这些 .sql 文件（禁止用 GORM AutoMigrate 建表）。
package migrations

import "embed"

// FS 是全部迁移文件。goose 以此为基准目录执行。
//
//go:embed *.sql
var FS embed.FS
