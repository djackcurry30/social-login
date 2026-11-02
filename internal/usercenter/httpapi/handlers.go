package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/djackcurry30/social-login/internal/pkg/metrics"
	"github.com/djackcurry30/social-login/internal/usercenter/domain"
	"github.com/djackcurry30/social-login/internal/usercenter/service"
	"github.com/djackcurry30/social-login/internal/usercenter/store/postgres"
)

// handler 持有各个端点需要的依赖。
type handler struct {
	svc   *service.Service
	log   *zap.Logger
	store *postgres.Store
	reg   *metrics.Registry
}

// claimDTO 是报文里的凭证。
//
// 单独定义而不是复用 domain.Claim：报文是契约，领域类型可以重构，
// 两者绑在一起会让"改个字段名"变成"改契约"。代价是几行转换代码。
type claimDTO struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// createAccount 处理 POST /v1/apps/{app_key}/accounts。
//
// 201 = 本次新建；200 = 幂等重放（同一账号）。
// 消费方对两者都按成功处理，区分它们只是为了让日志与指标能看出重放比例。
func (h *handler) createAccount(c *gin.Context) {
	app, ok := appFromContext(c)
	if !ok {
		fail(c, h.log, domain.New(domain.CodeInternal, "应用上下文缺失"))
		return
	}

	var body struct {
		Claims    []claimDTO `json:"claims"`
		Nickname  string     `json:"nickname"`
		AvatarURL string     `json:"avatar_url"`
	}
	if !bindJSON(c, h.log, &body) {
		return
	}

	claims := make([]domain.Claim, 0, len(body.Claims))
	for _, c2 := range body.Claims {
		claims = append(claims, domain.Claim{Type: c2.Type, Value: c2.Value, Source: c2.Source})
	}

	out, err := h.svc.Create(c.Request.Context(), app, service.CreateRequest{
		// 头名用标准写法：这是跨服务写操作的通用约定，用户中心也可能有
		// 别的调用方，各自发明前缀只会增加沟通成本。
		IdempotencyKey: trimParam(c.GetHeader(IdempotencyHeader)),
		Claims:         claims,
		Nickname:       body.Nickname,
		AvatarURL:      body.AvatarURL,
	})
	if err != nil {
		fail(c, h.log, err)
		return
	}

	status := http.StatusCreated
	if out.Replayed {
		status = http.StatusOK
	}
	c.JSON(status, out.Account)
}

// getAccount 处理 GET /v1/apps/{app_key}/accounts/{user_id}。
func (h *handler) getAccount(c *gin.Context) {
	app, ok := appFromContext(c)
	if !ok {
		fail(c, h.log, domain.New(domain.CodeInternal, "应用上下文缺失"))
		return
	}

	acc, err := h.svc.Get(c.Request.Context(), app, trimParam(c.Param("user_id")))
	if err != nil {
		fail(c, h.log, err)
		return
	}
	c.JSON(http.StatusOK, acc)
}

// getByClaim 处理 GET /v1/apps/{app_key}/accounts/by-claim?type=&value=。
//
// ⚠️ 消费方（social-login）依赖它是【强一致读】：归并前的最后一道防线。
// 本服务的连接池里没有只读副本，这条保证不靠文档，靠"没有第二条连接可用"。
func (h *handler) getByClaim(c *gin.Context) {
	app, ok := appFromContext(c)
	if !ok {
		fail(c, h.log, domain.New(domain.CodeInternal, "应用上下文缺失"))
		return
	}

	claimType := trimParam(c.Query("type"))
	value := c.Query("value")
	if claimType == "" || trimParam(value) == "" {
		failBadRequest(c, h.log, "缺少 type 或 value 查询参数")
		return
	}

	acc, err := h.svc.GetByClaim(c.Request.Context(), app, claimType, value)
	if err != nil {
		fail(c, h.log, err)
		return
	}
	c.JSON(http.StatusOK, acc)
}

// mergeAccounts 处理 POST /v1/apps/{app_key}/accounts/merge。
func (h *handler) mergeAccounts(c *gin.Context) {
	app, ok := appFromContext(c)
	if !ok {
		fail(c, h.log, domain.New(domain.CodeInternal, "应用上下文缺失"))
		return
	}

	var body struct {
		TargetUserID string `json:"target_user_id"`
		SourceUserID string `json:"source_user_id"`
		Reason       string `json:"reason"`
	}
	if !bindJSON(c, h.log, &body) {
		return
	}

	out, err := h.svc.Merge(c.Request.Context(), app, service.MergeRequest{
		IdempotencyKey: trimParam(c.GetHeader(IdempotencyHeader)),
		TargetUserID:   body.TargetUserID,
		SourceUserID:   body.SourceUserID,
		Reason:         body.Reason,
	})
	if err != nil {
		fail(c, h.log, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// replaceClaim 处理 PUT /v1/apps/{app_key}/accounts/{user_id}/claims/{claim_type}。
//
// 用 PUT 而不是 POST：这个动作是"把该类型凭证设成某值"，重复调用结果相同
// （已经是该值时返回 200 no-op）。语义上幂等，所以不需要 Idempotency-Key。
func (h *handler) replaceClaim(c *gin.Context) {
	app, ok := appFromContext(c)
	if !ok {
		fail(c, h.log, domain.New(domain.CodeInternal, "应用上下文缺失"))
		return
	}

	var body struct {
		Value  string `json:"value"`
		Source string `json:"source"`
	}
	if !bindJSON(c, h.log, &body) {
		return
	}
	if trimParam(body.Value) == "" {
		failBadRequest(c, h.log, "缺少 value")
		return
	}

	acc, err := h.svc.ReplaceClaim(c.Request.Context(), app,
		trimParam(c.Param("user_id")), trimParam(c.Param("claim_type")),
		body.Value, body.Source)
	if err != nil {
		fail(c, h.log, err)
		return
	}
	c.JSON(http.StatusOK, acc)
}

// registerApp 处理 POST /internal/v1/apps。
//
// 由 social-login 的注册同步任务调用（建应用时 + 每 5 分钟全量对账）。
// 语义必须是幂等 upsert：对账每 5 分钟重放一次全部应用。
func (h *handler) registerApp(c *gin.Context) {
	var body struct {
		AppKey string `json:"app_key"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if !bindJSON(c, h.log, &body) {
		return
	}

	app, err := h.svc.RegisterApp(c.Request.Context(), body.AppKey, body.Name, body.Status)
	if err != nil {
		fail(c, h.log, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"app_key": app.Key,
		"name":    app.Name,
		"status":  domain.AppStatusName(app.Status),
	})
}

// closeAccount 处理 POST /internal/v1/apps/{app_key}/accounts/{user_id}/close。
func (h *handler) closeAccount(c *gin.Context) {
	app, ok := appFromContext(c)
	if !ok {
		fail(c, h.log, domain.New(domain.CodeInternal, "应用上下文缺失"))
		return
	}

	userID := trimParam(c.Param("user_id"))
	if err := h.svc.Close(c.Request.Context(), app, userID); err != nil {
		fail(c, h.log, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": userID, "status": string(domain.StatusClosed)})
}
