package bootstrap

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// NewLogger 构造 zap 日志器。
//
// 选 zap 而不是 log/slog 的理由是生态而非性能（本服务日志量很低，性能差异无意义）：
// lumberjack 切割、zapcore 自定义 encoder、与 gin 访问日志的对接方案都更成熟，
// 团队也更熟悉（tech-stack §3.4）。
func NewLogger(cfg LogConfig) (*zap.Logger, error) {
	l, _, err := NewLoggerWithControl(cfg)
	return l, err
}

// NewLoggerWithControl 与 NewLogger 相同，但额外返回级别的原子句柄。
//
// 需要它的是"配置热更新"：日志级别是最该支持运行时调整的一项
// （线上把级别调到 debug 查一次问题，再调回来），而 zap 的 AtomicLevel
// 是唯一不需要重建 core 就能改级别的机制。
func NewLoggerWithControl(cfg LogConfig) (*zap.Logger, *zap.AtomicLevel, error) {
	lvl, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}
	// 用 AtomicLevel 而不是直接传 lvl：SetLevel 之后所有已生成的 logger
	// 立刻生效（core 持有的是同一个原子变量）。
	level := zap.NewAtomicLevelAt(lvl)

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeDuration = zapcore.MillisDurationEncoder

	var encoder zapcore.Encoder
	if strings.EqualFold(cfg.Format, "console") {
		encoderCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	} else {
		encoderCfg.EncodeLevel = zapcore.LowercaseLevelEncoder
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	}

	var ws zapcore.WriteSyncer
	if cfg.File != "" {
		// 生产环境写文件并切割。用 lumberjack 而不是自己按天切：
		// 自研切割在多进程写同一文件时会出现半行日志与文件竞争。
		ws = zapcore.AddSync(&lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAgeDays,
			Compress:   true,
		})
	} else {
		ws = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewCore(encoder, ws, level)
	logger := zap.New(core,
		// 加调用者信息：本服务的关键路径（登录/绑定）出问题时，
		// "哪一行日志"往往比"日志内容"更快定位问题。
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	return logger, &level, nil
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
		return zapcore.InfoLevel, errs.Newf(errs.CodeConfigInvalid, "未知的日志级别: %s", s)
	}
}
