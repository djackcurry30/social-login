package postgres

import "gorm.io/gorm"

// applyAppScope 把"应用维度"的过滤条件加到查询上。
//
// 三种状态，第三种最容易写错：
//
//	appID > 0       按单个应用过滤（调用方显式指定，中间件已校验在范围内）
//	appIDs == nil   不受限（全局管理员，或内部调用）
//	appIDs == []    一个应用都不许看 → 生成恒假条件
//
// 为什么单独抽出来：五个管理端列表都要这段判断，而"空切片 = 不过滤"
// 是这类隔离最典型的事故形态——它不报错，只是把全部数据放了出去。
func applyAppScope(q *gorm.DB, appID int64, appIDs []int64, column string) *gorm.DB {
	if appID > 0 {
		return q.Where(column+" = ?", appID)
	}
	if appIDs == nil {
		return q
	}
	if len(appIDs) == 0 {
		// 不能用 "IN (NULL)"：它在语义上是"未知"，不是"假"。
		return q.Where("1 = 0")
	}
	return q.Where(column+" IN ?", appIDs)
}
