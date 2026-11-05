package postgres

import "testing"

// TestOneLine 守住"一条 SQL 一行日志"。
//
// 不压的情况很具体：仓储层的 SQL 都是缩进的多行字符串，直接打日志会让
// 一条语句散成十几行，grep 不到、日志平台的重试聚合也认不出来。
func TestOneLine(t *testing.T) {
	in := "SELECT id,\n\t status\n  FROM accounts\n WHERE app_id = $1"
	got := oneLine(in)
	want := "SELECT id, status FROM accounts WHERE app_id = $1"
	if got != want {
		t.Fatalf("压行结果不符:\n got=%q\nwant=%q", got, want)
	}
}

// TestClipLimitsRunes 确认截断按字符而不是字节。
//
// 按字节截会把中文切成半个 rune，日志里出现乱码（还会让 JSON 输出非法）。
func TestClipLimitsRunes(t *testing.T) {
	if got := clip("一二三四五", 3); got != "一二三" {
		t.Fatalf("应截成 3 个字符，实际 %q", got)
	}
	if got := clip("ab", 5); got != "ab" {
		t.Fatalf("不足上限时不应改动，实际 %q", got)
	}
}
