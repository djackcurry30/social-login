// http_registry.go 实现"把应用注册到用户中心"（契约 v1.1 §4.2）。
//
// 这个端点与账号接口不同：它【不在应用前缀下】——它本身就是"声明一个应用存在"，
// 再套一层 /v1/apps/{app_key}/apps 没有意义。
//
//	POST {base}/internal/v1/apps
//	     {"app_key":"app_xxx","name":"应用一","status":"active","updated_at":"..."}
//	     → 200/201/204 幂等 upsert 成功
//	     → 400 + {"code":"INVALID.REQUEST"} 报文不合法
//	     → 5xx / 超时 → 可重试
//
// 为什么放在 /internal 下：它是服务间接口（只有本服务调用），与面向业务方的
// /v1 分开，网关层可以直接对 /internal/* 做来源限制——这是个只有内网才该
// 存在的写入口。
package account

import (
	"context"
	"net/http"
	"strings"
	"time"

	domainaccount "github.com/djackcurry30/social-login/internal/domain/account"
	"github.com/djackcurry30/social-login/internal/pkg/errs"
)

// registryPath 是应用注册端点。
const registryPath = "/internal/v1/apps"

// 编译期断言：HTTPProvider 同时是账号接口与注册接口的实现。
var _ domainaccount.AppRegistrar = (*HTTPProvider)(nil)

// RegisterApp 把应用同步到用户中心。
//
// 幂等由对端保证（upsert）：对账任务每 5 分钟会把全部应用重放一遍，
// 这里刻意【不做本地去重】（比如"上次同步过就跳过"）——那样就再也发现不了
// "对端数据被回滚"这类漂移，而重放恰恰是自愈手段本身。
func (p *HTTPProvider) RegisterApp(ctx context.Context, reg domainaccount.AppRegistration) error {
	if strings.TrimSpace(reg.AppKey) == "" {
		// 空 app_key 打到对端会在它的租户表里造出一条空记录，或者被路由成
		// 别的语义。这种参数错误必须在本地暴露（是我方装配问题，不是对端问题）。
		return errs.New(errs.CodeInternal, "注册应用缺少 app_key")
	}
	if reg.Status == "" {
		// 不默认成 active：默认启用会让一个已停用的应用在对端被重新启用，
		// 而"停用"通常是出于安全或合规原因。
		return errs.New(errs.CodeInternal, "注册应用缺少状态")
	}

	body := map[string]any{
		"app_key": reg.AppKey,
		"name":    reg.Name,
		"status":  string(reg.Status),
	}
	if !reg.LocalUpdatedAt.IsZero() {
		// 对端当前不需要这个字段，带上是为了 P1 能判断"谁更新"而不必改契约。
		body["updated_at"] = reg.LocalUpdatedAt.UTC().Format(time.RFC3339Nano)
	}

	resp, err := p.call(ctx, http.MethodPost, p.baseURL+registryPath, body, nil)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return nil
	}
	// 其余一律走统一翻译：400 裸响应会译成 ACCOUNT.UNAVAILABLE（不可重试），
	// 5xx 会译成可重试——这与"下一轮对账再试"的重试语义正好对上。
	return p.classify("RegisterApp", resp)
}
