package bootstrap

import (
	"strings"
	"testing"
)

// describeAccountCenter 是看板上的"账号体系现状"标记，逻辑简单但影响判断：
// 它错报成 ready，运维就会以为已经接上真实用户中心。
func TestDescribeAccountCenter(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		baseURL  string
		token    string
		wantMode string
		wantURL  string
		wantOK   bool
		wantNote string // 期望 Note 包含的片段
	}{
		{
			name:     "未配置视为 stub",
			provider: "",
			wantMode: "stub",
			wantNote: "进程内存",
		},
		{
			name:     "大小写与空格需归一化",
			provider: "  STUB ",
			wantMode: "stub",
		},
		{
			name:     "http 且有 token",
			provider: "http",
			baseURL:  "https://uc.internal",
			token:    "t",
			wantMode: "http",
			wantURL:  "https://uc.internal",
			wantOK:   true,
			wantNote: "已接用户中心",
		},
		{
			name:     "http 缺 token 必须提示",
			provider: "http",
			baseURL:  "http://uc:8080",
			wantMode: "http",
			wantURL:  "http://uc:8080",
			wantOK:   true,
			wantNote: "token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Account.Provider = tc.provider
			cfg.Account.HTTP.BaseURL = tc.baseURL
			cfg.Account.HTTP.Token = tc.token

			got := describeAccountCenter(cfg)
			if got.Provider != tc.wantMode {
				t.Fatalf("provider 期望 %q，实际 %q", tc.wantMode, got.Provider)
			}
			if got.BaseURL != tc.wantURL {
				t.Fatalf("base_url 期望 %q，实际 %q", tc.wantURL, got.BaseURL)
			}
			if got.ProductionReady != tc.wantOK {
				t.Fatalf("production_ready 期望 %v，实际 %v", tc.wantOK, got.ProductionReady)
			}
			if !strings.Contains(got.Note, tc.wantNote) {
				t.Fatalf("note 应包含 %q，实际 %q", tc.wantNote, got.Note)
			}
		})
	}
}
