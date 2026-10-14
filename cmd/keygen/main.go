// Command keygen 生成运行所需的密钥材料。
//
// 用法：
//
//	go run ./cmd/keygen                      # 只生成主密钥（信封加密用）
//	go run ./cmd/keygen -out keys/ -kid k1   # 同时生成 JWT 签名密钥（ES256）
//
// 生成结果直接粘贴到配置文件或注入环境变量即可。私钥文件权限会被设为 0600。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/djackcurry30/social-login/internal/infrastructure/crypto"
)

func main() {
	var (
		outDir = flag.String("out", "", "签名私钥输出目录（留空则只生成主密钥）")
		kid    = flag.String("kid", "", "签名密钥版本标识（留空则自动生成）")
	)
	flag.Parse()

	// 1) 信封加密主密钥（32 字节）。
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		fail("生成主密钥失败", err)
	}
	fmt.Println("# ==== 渠道凭据信封加密主密钥 ====")
	fmt.Printf("# 写入配置 security.master_key，或环境变量 SOCIAL_LOGIN_SECURITY_MASTER_KEY\n")
	fmt.Printf("security.master_key: \"%s\"\n\n", crypto.EncodeMasterKey(masterKey))

	fmt.Println("# ==== 凭证哈希盐 ====")
	fmt.Println("# ⚠️ 必须保持稳定：变更它会让已入库的 claim 哈希全部无法匹配，")
	fmt.Println("#    \"按手机号归并\"能力会整体失效。")
	claimSalt := randomHex(32)
	appSecretSalt := randomHex(32)
	fmt.Printf("security.claim_salt: \"%s\"\n", claimSalt)
	fmt.Printf("security.app_secret_salt: \"%s\"\n\n", appSecretSalt)

	if *outDir == "" {
		fmt.Println("# 如需 JWT 签名密钥，重新执行并加上 -out 参数（生产环境必需）。")
		return
	}

	// 2) JWT 签名密钥（ES256 / P-256）。
	if *kid == "" {
		*kid = "k-" + randomHex(6)
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fail("创建输出目录失败", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail("生成签名密钥失败", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fail("序列化签名密钥失败", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	path := filepath.Join(*outDir, *kid+".pem")
	// 0600：私钥只有属主可读写。世界可读的私钥是最常见的一类泄漏。
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		fail("写入签名密钥失败", err)
	}

	fmt.Printf("# ==== JWT 签名密钥（ES256）====\n")
	fmt.Printf("# 私钥已写入：%s（权限 0600）\n", path)
	fmt.Printf("# ⚠️ 该文件不得进版本库（.gitignore 已忽略 *.pem）\n")
	fmt.Printf("jwt:\n  signing_keys:\n    - kid: \"%s\"\n      private_key_file: \"%s\"\n", *kid, path)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		fail("生成随机数失败", err)
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, b := range buf {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}
