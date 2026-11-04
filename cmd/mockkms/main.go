// Command mockkms 在本地起一个假 KMS，用于演练"本地主密钥 → KMS"的切换。
//
//	go run ./cmd/mockkms -addr 127.0.0.1:9091
//
// 然后把 configs/config.yaml 的 security.kms 指向它：
//
//	kms:
//	  enabled: true
//	  base_url: "http://127.0.0.1:9091"
//	  key_id: "kek-kms-v1"
//
// ⚠️ 仅供本地与测试。密钥在进程内存、无审计、无 HSM。
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/djackcurry30/social-login/internal/testsupport/mockkms"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9091", "监听地址")
	masterB64 := flag.String("master-key", "",
		"固定的 KMS 主密钥（Base64，32 字节）。留空则随机生成并打印——"+
			"重启会换密钥，用旧密钥包装过的密文将全部解不开")
	flag.Parse()

	var master []byte
	if *masterB64 != "" {
		key, err := base64.StdEncoding.DecodeString(*masterB64)
		if err != nil {
			log.Fatalf("解析 -master-key 失败: %v", err)
		}
		master = key
	}
	srv, used, err := mockkms.New(master)
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}
	log.Printf("KMS 主密钥（Base64，重启时用 -master-key 传回来即可固定）: %s",
		base64.StdEncoding.EncodeToString(used))
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("mock KMS 监听 %s（/v1/wrap /v1/unwrap /healthz）", *addr)
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("启动失败: %v", err)
	}
}
