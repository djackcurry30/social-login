// Command mockoauth2 启动一个最小可用的 OAuth2 提供方，用于本地联调。
//
// 用法：
//
//	go run ./cmd/mockoauth2 -addr 127.0.0.1:9090
//
// 然后按 cmd/seed 的说明把渠道配置指向它即可在不依赖任何真实平台的情况下
// 走通"授权 → 回调 → NEED_REGISTER → 绑定 → 签发令牌"的完整链路。
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/17track/social-login/internal/testsupport/mockoauth2"
)

func main() {
	var (
		addr         = flag.String("addr", "127.0.0.1:9090", "监听地址")
		clientID     = flag.String("client-id", "mock-client", "认可的 client_id")
		clientSecret = flag.String("client-secret", "mock-secret", "认可的 client_secret")
		subject      = flag.String("subject", "mock-user-1", "默认用户标识")
	)
	flag.Parse()

	srv := mockoauth2.New(mockoauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		DefaultProfile: mockoauth2.Profile{
			Subject: *subject,
			Name:    "Mock User",
			Email:   "mock@example.com",
			Picture: "https://example.com/avatar.png",
		},
	})

	fmt.Fprintf(os.Stderr, "mock OAuth2 提供方已启动: http://%s\n", *addr)
	fmt.Fprintf(os.Stderr, "  authorize: http://%s/oauth/authorize\n", *addr)
	fmt.Fprintf(os.Stderr, "  token:     http://%s/oauth/token\n", *addr)
	fmt.Fprintf(os.Stderr, "  userinfo:  http://%s/oauth/userinfo\n", *addr)
	fmt.Fprintf(os.Stderr, "提示：/oauth/authorize 支持 login_hint / mock_phone / mock_email 参数，\n")
	fmt.Fprintf(os.Stderr, "      可用于构造\"换一个用户\"或\"带手机号\"的测试场景。\n")

	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatalf("mock OAuth2 启动失败: %v", err)
	}
}
