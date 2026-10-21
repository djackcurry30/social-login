// Package sms 是验证码发送端口的实现。
//
// 当前只提供"日志通道"：它把验证码打进日志，供开发与集成测试使用。
// 生产必须换成真实的短信服务商实现（阿里云 / 腾讯云 SMS），
// 且启动自检要拒绝在 release 模式下使用日志通道——否则用户永远收不到码，
// 表现为"合并流程走到一半就没反应"，比直接报错难查得多。
package sms

import (
	"context"

	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/domain/merge"
)

// LogSender 把验证码写入日志，供开发与测试使用。
type LogSender struct {
	logger *zap.Logger
}

// NewLogSender 构造日志通道。
func NewLogSender(logger *zap.Logger) *LogSender {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &LogSender{logger: logger}
}

var _ merge.CodeSender = (*LogSender)(nil)

// Send 记录验证码而不真正发送。
//
// ⚠️ 这里刻意打印明文 code：开发阶段没有真实短信通道，不打印就无法联调。
// 生产环境不会使用本实现（见 Package 注释的启动自检要求）。
func (s *LogSender) Send(_ context.Context, req merge.CodeRequest) error {
	s.logger.Warn("验证码未真实发送（日志通道）",
		zap.String("phone", Mask(req.Phone)),
		zap.String("purpose", req.Purpose),
		zap.String("code", req.Code),
		zap.Duration("ttl", req.TTL))
	return nil
}

// UnconfiguredSender 在未接短信通道时使用：明确报错而不是静默成功。
//
// 静默成功会让用户以为"码已发出"，然后一直等一条永远不来的短信。
type UnconfiguredSender struct{}

// NewUnconfiguredSender 构造未配置通道。
func NewUnconfiguredSender() *UnconfiguredSender { return &UnconfiguredSender{} }

var _ merge.CodeSender = (*UnconfiguredSender)(nil)

// Send 返回配置错误。
func (s *UnconfiguredSender) Send(context.Context, merge.CodeRequest) error {
	return errNoSMSChannel
}

// errNoSMSChannel 用普通 error 而不是 errs.Error：调用方会把它包进
// CONFIG.INVALID，保持错误码语义集中在用例层。
var errNoSMSChannel = errSMSNotConfigured{}

type errSMSNotConfigured struct{}

func (errSMSNotConfigured) Error() string {
	return "未配置短信通道（sms.provider），无法发送验证码"
}

// Mask 掩码手机号：保留前 3 与后 2 位。
//
// 日志、响应、审计里一律用掩码——验证码短信本身就带号码，
// 再在别处留一份完整号码没有任何收益。
func Mask(phone string) string {
	r := []rune(phone)
	if len(r) <= 5 {
		return "***"
	}
	return string(r[:3]) + "****" + string(r[len(r)-2:])
}
