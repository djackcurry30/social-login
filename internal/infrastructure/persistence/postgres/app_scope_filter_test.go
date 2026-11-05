package postgres

import (
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type scopeProbe struct {
	ID    int64
	AppID int64 `gorm:"column:app_id"`
}

func (scopeProbe) TableName() string { return "probe" }

// TestApplyAppScope 校验四种状态生成的 SQL。
//
// 用 DryRun + ToSQL 而不是连真库：这里要验的是"条件有没有加上"，
// 属纯字符串逻辑；连库反而会把环境依赖塞进一条本来很快的用例。
func TestApplyAppScope(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: "postgres://user:pass@127.0.0.1:1/none?sslmode=disable",
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("构造 DryRun 连接失败: %v", err)
	}

	cases := []struct {
		name    string
		appID   int64
		appIDs  []int64
		want    []string
		notWant []string
	}{
		{
			name:    "不受限：不出现 app_id 条件",
			appID:   0,
			appIDs:  nil,
			notWant: []string{"app_id", "1 = 0"},
		},
		{
			name:  "显式单应用",
			appID: 9,
			want:  []string{"app_id = 9"},
		},
		{
			name:   "多应用范围",
			appID:  0,
			appIDs: []int64{3, 7},
			want:   []string{"app_id IN (3,7)"},
		},
		{
			name:   "范围为空 → 恒假条件（不能退化成不过滤）",
			appID:  0,
			appIDs: []int64{},
			want:   []string{"1 = 0"},
		},
		{
			name:    "单应用优先于范围",
			appID:   9,
			appIDs:  []int64{3, 7},
			want:    []string{"app_id = 9"},
			notWant: []string{"IN ("},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rows []scopeProbe
			sql := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
				q := applyAppScope(tx.Model(&scopeProbe{}), tc.appID, tc.appIDs, "app_id")
				return q.Find(&rows)
			})
			for _, w := range tc.want {
				if !strings.Contains(sql, w) {
					t.Fatalf("SQL 应包含 %q，实际: %s", w, sql)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(sql, nw) {
					t.Fatalf("SQL 不应包含 %q，实际: %s", nw, sql)
				}
			}
		})
	}
}
