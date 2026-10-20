# ============================================================
#  三方登录统一接入服务 · 单镜像多阶段构建
#
#  产物是一个包含「Go 后端 + 内嵌 React 管理端」的镜像：
#    /app/bin/social-login   HTTP 服务（含 /admin 前端）
#    /app/bin/migrate        数据库迁移（init 容器用）
#    /app/bin/adminseed      写入本地管理员（init 容器用）
#    /app/configs/config.yaml 默认配置（compose 用环境变量覆盖）
#
#  构建：docker build -t social-login:local .
#  或：  docker compose up --build
#
#  国内网络默认走 daocloud 镜像源 + goproxy.cn + npmmirror，
#  全部可用 --build-arg 覆盖。
# ============================================================

ARG REGISTRY=docker.m.daocloud.io/library


# ------------------------------------------------------------
# Stage 1 · 构建管理端前端（Vite + React + TS）
# ------------------------------------------------------------
FROM ${REGISTRY}/node:22-alpine AS web-builder

# 国内默认走 npmmirror；如网络可直连 npmjs 可覆盖为 https://registry.npmjs.org
ARG NPM_REGISTRY=https://registry.npmmirror.com

WORKDIR /web

# 先只拷贝清单文件，让依赖层可被缓存（改业务代码不会重装依赖）
COPY web/package.json web/package-lock.json ./

# package-lock.json 里的 resolved 指向 registry.npmjs.org，
# npm ci 会照搬这些 URL 而绕过 registry 配置；先就地改写主机名。
RUN npm config set registry "${NPM_REGISTRY}" \
 && sed -i "s#https://registry.npmjs.org#${NPM_REGISTRY}#g" package-lock.json \
 && npm ci --no-audit --no-fund

COPY web/ ./

RUN npm run build

# 产出：/web/dist（index.html + assets/）


# ------------------------------------------------------------
# Stage 2 · 构建 Go 二进制，并把前端产物嵌入
# ------------------------------------------------------------
FROM ${REGISTRY}/golang:1.26-alpine AS go-builder

ARG GOPROXY=https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.google.cn
ARG VERSION=docker

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOPROXY=${GOPROXY} \
    GOSUMDB=${GOSUMDB}

WORKDIR /src

# 依赖层可缓存
COPY go.mod go.sum ./
RUN go mod download

# 源码
COPY . ./

# ⚠️ 关键：用 Stage 1 的产物覆盖 embedweb/dist。
# 这一步必须放在 COPY . ./ 之后，否则会被上下文里的旧产物盖回去。
COPY --from=web-builder /web/dist ./internal/embedweb/dist

# 静态二进制：alpine 运行时无需 glibc
RUN set -eux; \
    LDFLAGS="-s -w -X github.com/djackcurry30/social-login/internal/bootstrap.Version=${VERSION}"; \
    go build -trimpath -ldflags "${LDFLAGS}" -o /out/social-login ./cmd/server; \
    go build -trimpath -ldflags "-s -w"    -o /out/migrate      ./cmd/migrate; \
    go build -trimpath -ldflags "-s -w"    -o /out/adminseed    ./cmd/adminseed; \
    ls -lh /out


# ------------------------------------------------------------
# Stage 3 · 运行时
# ------------------------------------------------------------
FROM ${REGISTRY}/alpine:3.20 AS runtime

# alpine 默认源 dl-cdn.alpinelinux.org 在部分网络下不可达，换成国内镜像。
ARG APK_MIRROR=mirrors.aliyun.com

# ca-certificates：调三方平台 HTTPS 必需
# tzdata：日志与令牌过期时间按本地时区可读
RUN sed -i "s#dl-cdn.alpinelinux.org#${APK_MIRROR}#g" /etc/apk/repositories \
 && apk add --no-cache ca-certificates tzdata \
 && addgroup -S app \
 && adduser  -S -G app -h /app app

WORKDIR /app

COPY --from=go-builder /out/social-login /app/bin/social-login
COPY --from=go-builder /out/migrate      /app/bin/migrate
COPY --from=go-builder /out/adminseed    /app/bin/adminseed
COPY configs/config.yaml /app/configs/config.yaml

# 运行用户不写文件，目录只读即可——除了审计导出目录。
#
# ⚠️ 这里必须【预先建好并 chown】：compose 把 named volume 挂在
# /app/var/exports 上，而 Docker 初始化一个空 named volume 时，会把镜像里
# 该路径的【属主与权限】复制过去。镜像里没有这个目录时，Docker 会以
# root:root 新建，运行用户 uid=100(app) 随即失去写权限，表现是
# "导出任务永远 failed: permission denied"，且启动阶段毫无提示。
RUN chown -R app:app /app \
 && mkdir -p /app/var/exports \
 && chown -R app:app /app/var

USER app

EXPOSE 8080

# busybox wget 已随 alpine 提供，无需额外安装
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=12 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1

CMD ["/app/bin/social-login", "-config", "/app/configs/config.yaml"]
