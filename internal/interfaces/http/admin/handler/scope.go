package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/djackcurry30/social-login/internal/interfaces/http/adminmw"
)

// scopeAppIDs 取当前管理员的应用范围，供列表查询下推到 SQL。
//
// 返回 nil 表示不受限（列表不过滤）；受限时返回范围，**可能为空切片**——
// 那表示"一个应用都不许看"，此时查询必须返回空结果而不是全部数据。
// 把这个语义留在这一处，避免每个 handler 各写一遍 nil/空 的判断。
func scopeAppIDs(c *gin.Context) []int64 {
	ids, restricted := adminmw.ScopeAppIDs(c)
	if !restricted {
		return nil
	}
	if ids == nil {
		// 受限但范围为空：用非 nil 空切片表达"一个都不许看"，
		// nil 会被下游当成"不过滤"，把全部应用的数据放出去。
		return []int64{}
	}
	return ids
}
