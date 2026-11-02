// Command mockusercenter 启动一个按契约实现的假用户中心，用于联调与演示。
//
// 用法：
//
//	go run ./cmd/mockusercenter -addr 127.0.0.1:9091 -app app_web_portal
//
// 然后让本服务指向它：
//
//	SOCIAL_LOGIN_ACCOUNT_PROVIDER=http \
//	SOCIAL_LOGIN_ACCOUNT_HTTP_BASE_URL=http://127.0.0.1:9091 \
//	go run ./cmd/server
//
// 容器内跑时把 127.0.0.1 换成宿主机地址（macOS/Windows 为
// host.docker.internal）。
//
// ⚠️ 契约 v1.1 起所有路径带应用前缀，`-app` 必须与本服务里的
// applications.app_code 一致，否则对端会把它当成另一个租户（账号查不到）。
//
// 预置账号（模拟"用户中心里已经存在的账号"，用于验证归并与回源核对）：
//
//	go run ./cmd/mockusercenter -app app_web_portal \
//	  -seed "phone:13800000001:wechat_phone,email:a@example.com:apple_email"
//
// 模拟"应用未注册"（验证 APP.UNKNOWN 的降级文案）：
//
//	go run ./cmd/mockusercenter -apps app_one,app_two
//	# 此时请求 app_web_portal 会得到 400 APP.UNKNOWN
//
// 也可以不给 -apps，让本服务的注册同步任务自己把应用注册上来：
//
//	go run ./cmd/mockusercenter -require-apps
//	# 初始一个应用都没有；等登录中心的同步跑过一轮（最多 5 分钟，或建应用时
//	# 触发即时同步）之后，对应应用才可用。
//	# 这条路径验的正是 §2.6：应用注册是登录的前置条件。
//
// 为什么要有这个命令（而不是只留测试包）：
// 用户中心还没建之前，`account.provider=http` 需要有东西可指。否则这条路径
// 只能等对端就绪那天才第一次被真实跑起来——那一天会同时暴露协议、幂等、
// 超时、降级四类问题，而它们本该在不同时间点各自暴露。
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/djackcurry30/social-login/internal/testsupport/mockusercenter"
)

func main() {
	var (
		addr              = flag.String("addr", "127.0.0.1:9091", "监听地址")
		token             = flag.String("token", "", "要求调用方携带的 Bearer token（空表示不校验）")
		createUnsupported = flag.Bool("no-create", false, "模拟用户中心不提供创建账号能力（Create 返回 404）")
		appKey            = flag.String("app", "app_demo", "预置账号所属的应用（= applications.app_code）")
		apps              = flag.String("apps", "", "已注册应用（逗号分隔）。给了就启用「未注册即 400 APP.UNKNOWN」")
		requireApps       = flag.Bool("require-apps", false, "启用「未注册即 400 APP.UNKNOWN」，但不预置任何应用（等同步任务注册）")
		seedSpec          = flag.String("seed", "", "预置账号的凭证，格式 type:value[:source]，逗号分隔")
	)
	flag.Parse()

	srv := mockusercenter.New(mockusercenter.Config{
		Token:                *token,
		CreateUnsupported:    *createUnsupported,
		RequireRegisteredApp: strings.TrimSpace(*apps) != "" || *requireApps,
	})
	for _, a := range strings.Split(*apps, ",") {
		if a = strings.TrimSpace(a); a != "" {
			srv.RegisterApp(a)
		}
	}

	if *seedSpec != "" {
		claims, err := parseSeed(*seedSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "解析 -seed 失败: %v\n", err)
			os.Exit(2)
		}
		uid := srv.Seed(*appKey, "", claims)
		fmt.Fprintf(os.Stderr, "已预置账号 %s（应用 %s），凭证 %d 条\n", uid, *appKey, len(claims))
	}

	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "假用户中心已启动: http://%s\n", *addr)
	fmt.Fprintf(os.Stderr, "  GET  /v1/apps/{app_key}/accounts/{user_id}\n")
	fmt.Fprintf(os.Stderr, "  GET  /v1/apps/{app_key}/accounts/by-claim?type=&value=\n")
	fmt.Fprintf(os.Stderr, "  POST /v1/apps/{app_key}/accounts              (需 Idempotency-Key)\n")
	fmt.Fprintf(os.Stderr, "  POST /v1/apps/{app_key}/accounts/merge        (需 Idempotency-Key)\n")
	fmt.Fprintf(os.Stderr, "  PUT  /v1/apps/{app_key}/accounts/{id}/claims/{type}\n")
	fmt.Fprintf(os.Stderr, "  POST /internal/v1/apps                        (服务间：应用注册，幂等 upsert)\n")
	fmt.Fprintf(os.Stderr, "  GET  /healthz\n")
	if strings.TrimSpace(*apps) != "" {
		fmt.Fprintf(os.Stderr, "  只接受已注册应用: %s\n", *apps)
	} else if *requireApps {
		fmt.Fprintf(os.Stderr, "  只接受已注册应用：当前一个都没有，等同步任务注册\n")
	}
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("启动失败: %v", err)
	}
}

// parseSeed 解析 "phone:138...,email:..."。
//
// source 可省略：省略时留空。留空的后果是这条凭证不满足 R4 白名单，
// 因此【不会】参与自动归并——想验证归并必须显式写 source。
func parseSeed(spec string) ([]mockusercenter.Claim, error) {
	var out []mockusercenter.Claim
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f := strings.SplitN(part, ":", 3)
		if len(f) < 2 || strings.TrimSpace(f[0]) == "" || strings.TrimSpace(f[1]) == "" {
			return nil, fmt.Errorf("格式应为 type:value[:source]，得到 %q", part)
		}
		c := mockusercenter.Claim{Type: strings.TrimSpace(f[0]), Value: strings.TrimSpace(f[1])}
		if len(f) == 3 {
			c.Source = strings.TrimSpace(f[2])
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-seed 未解析出任何凭证")
	}
	return out, nil
}
