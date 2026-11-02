// Package observe 是用户中心的可观测性：结构化日志与 Prometheus 指标。
//
// 只复用 social-login 的 internal/pkg/metrics（一个不依赖业务的文本导出器），
// 日志器自己写：那个包的 NewLogger 挂在 bootstrap 下，会把整条 social-login
// 启动链（gin、gorm、渠道适配器）链接进用户中心的二进制。
package observe

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/djackcurry30/social-login/internal/usercenter/domain"
)

// NewLogger 构造 zap 日志器。
//
// 默认输出到 stdout：本服务是无状态容器，日志应该由编排层收集，
// 而不是写进容器内的文件（容器一重启文件就没了，排查时只能看到重启后的部分）。
// 配了 log.file 才写文件，此时不做切割——真要落盘请用 sidecar/logrotate，
// 自己实现切割在多副本写同一文件时会出现半行日志。
func NewLogger(level, format, file string) (*zap.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeDuration = zapcore.MillisDurationEncoder

	var encoder zapcore.Encoder
	if strings.EqualFold(format, "console") {
		encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encCfg)
	} else {
		encCfg.EncodeLevel = zapcore.LowercaseLevelEncoder
		encoder = zapcore.NewJSONEncoder(encCfg)
	}

	ws := zapcore.AddSync(os.Stdout)
	if file != "" {
		f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, domain.New(domain.CodeInternal, "打开日志文件失败").WithCause(err)
		}
		ws = zapcore.AddSync(f)
	}

	return zap.New(zapcore.NewCore(encoder, ws, lvl), zap.AddCaller()), nil
}

func parseLevel(s string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return zapcore.InfoLevel, nil
	case "debug":
		return zapcore.DebugLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("未知的日志级别: %s", s)
	}
}
