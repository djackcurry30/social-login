package postgres

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// zapLogger 把 GORM 的日志接到 zap 上。
//
// 为什么不用 GORM 默认 logger：它直接写 stdout、格式与业务日志不一致，
// 且慢查询阈值不可配。这里保持一个薄适配，不引入 gorm 的第三方 zap 适配包
// （少一个依赖；逻辑本身只有几十行）。
type zapLogger struct {
	log           *zap.Logger
	level         gormlogger.LogLevel
	slowThreshold time.Duration
}

func newZapLogger(log *zap.Logger, slowThreshold time.Duration, logSQL bool) gormlogger.Interface {
	if slowThreshold <= 0 {
		slowThreshold = 200 * time.Millisecond
	}
	lvl := gormlogger.Warn
	if logSQL {
		lvl = gormlogger.Info
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &zapLogger{log: log.Named("gorm"), level: lvl, slowThreshold: slowThreshold}
}

// LogMode 实现 gormlogger.Interface。
func (z *zapLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	clone := *z
	clone.level = level
	return &clone
}

func (z *zapLogger) Info(ctx context.Context, msg string, args ...any) {
	if z.level >= gormlogger.Info {
		z.log.Sugar().Infof(msg, args...)
	}
}

func (z *zapLogger) Warn(ctx context.Context, msg string, args ...any) {
	if z.level >= gormlogger.Warn {
		z.log.Sugar().Warnf(msg, args...)
	}
}

func (z *zapLogger) Error(ctx context.Context, msg string, args ...any) {
	if z.level >= gormlogger.Error {
		z.log.Sugar().Errorf(msg, args...)
	}
}

// Trace 实现 gormlogger.Interface。
//
// 关键点：区分"慢查询"与"真错误"。gorm.ErrRecordNotFound 是正常的业务分支
// （例如查不到活跃绑定），不能按错误级别打日志，否则日志会被正常流程刷满。
func (z *zapLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if z.level <= gormlogger.Silent {
		return
	}
	elapsed := time.Since(begin)
	sql, rows := fc()

	fields := []zap.Field{
		zap.String("sql", sql),
		zap.Int64("rows", rows),
		zap.Duration("elapsed", elapsed),
	}

	switch {
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
		z.log.Error("db_error", append(fields, zap.Error(err))...)
	case z.level >= gormlogger.Info:
		z.log.Debug("db_query", fields...)
	}

	if z.slowThreshold > 0 && elapsed > z.slowThreshold {
		z.log.Warn("db_slow_query",
			zap.String("sql", sql),
			zap.Duration("elapsed", elapsed),
			zap.Duration("threshold", z.slowThreshold))
	}
}

var _ gormlogger.Interface = (*zapLogger)(nil)
