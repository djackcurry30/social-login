// Package usercenter 把用户中心的 SQL 迁移文件嵌入二进制。
//
// 为什么与 social-login 的 migrations 包分开：
//
//	两边是【两个服务、两个数据库】。共用一个迁移目录会带来两个具体问题：
//	  1. goose 的顺序执行会让 social-login 的迁移把 UC 的表也建出来（或反之），
//	     于是"某个服务没部署"在数据库里看不出来，只在真正调用时 500；
//	  2. 任何一方加迁移都可能改变另一方的版本号基线，回滚粒度被绑死。
//
//	代价是两个目录都要维护，但这是"跨服务边界"应有的成本。
package usercenter

import "embed"

// FS 是用户中心的全部迁移文件。
//
//go:embed *.sql
var FS embed.FS
