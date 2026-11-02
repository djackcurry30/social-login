package account

import (
	"context"
	"time"
)

// AppStatus 是应用在用户中心的启用状态。
//
// 为什么不直接透传 applications.status（int16）：
// 契约里用数字表示状态，一旦要加第三种状态（例如"灰度中"），只能靠约定
// 数字含义，而字符串是自解释的。跨服务契约的取值应该按"读的人能看懂"来选。
type AppStatus string

const (
	// AppStatusActive 表示应用启用，可以登录、建号。
	AppStatusActive AppStatus = "active"
	// AppStatusDisabled 表示应用已停用。
	//
	// 注意：同步它只是"把事实告诉用户中心"。用户中心是否据此拒绝该应用的
	// 请求属于交互策略，MVP 阶段不做（§12.3），所以停用后在登录链路上
	// 依然是本服务先拒——那一层在本地的 applications.status 检查里。
	AppStatusDisabled AppStatus = "disabled"
)

// AppRegistration 是要同步给用户中心的租户记录。
//
// 刻意【不包含任何凭据】：app_secret 是发给业务方的，不该扩散到内部服务；
// 用户中心只需要知道"这个 app_key 存在、叫什么、是否启用"。
type AppRegistration struct {
	// AppKey 取 applications.app_code，与登录链路里 Create / Merge / Get 用的
	// 是同一个值。两边必须一致，否则会出现"注册了 A、登录时带的是 B"这种
	// 静默失配——表现是所有登录都 400 APP.UNKNOWN，但注册同步却"成功"。
	AppKey string
	// Name 仅供对端排查（例如运维在用户中心里认应用）。
	Name string
	// Status 是启用状态。
	Status AppStatus
	// LocalUpdatedAt 是本地最后修改时间，随报文带给对端。
	// 当前对端不需要它，带上是为了 P1 能判断"谁更新"而不必改契约。
	LocalUpdatedAt time.Time
}

// AppRegistrar 是把应用注册到用户中心的可选端口。
//
// 为什么是【可选端口】而不是 Provider 的方法：
//
//   - 生命周期不同。Provider 是每次登录都要用的东西；注册只发生在"建应用"
//     与"定时对账"两个时刻。
//   - 桩实现根本没有"注册"这件事。让 StubAccountProvider 实现一个空方法，
//     同步状态就会显示"已同步"，而实际上并不存在用户中心——一个会撒谎的
//     状态比没有状态更糟。没有这个能力时就不装配，整个同步服务关闭。
//
// 实现方要求：必须【幂等】（upsert）。对账任务每 5 分钟会把全部应用重放一遍，
// 不幂等的实现会不断造出重复租户，而重复租户在账号侧的表现是"用户被随机
// 分到其中一份，另一半数据永远查不到"。
type AppRegistrar interface {
	RegisterApp(ctx context.Context, reg AppRegistration) error
}
