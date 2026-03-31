package scouter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"math"
	"net"
	"net/http"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"
)

/*
默认配置:
默认速率 (DefaultRate): 50 QPS
默认时长 (DefaultDuration): 10秒
默认超时 (DefaultTimeout): 30秒
默认请求方法 (DefaultMethod): GET
默认并发协程 (DefaultWorkers): 10
最大并发上限 (DefaultMaxWorkers): 无限制
响应体上限 (DefaultMaxBody): 不限制 (-1)
最大连接数 (DefaultConnections): 10000
*/
const (
	DefaultRate        = 50
	DefaultDuration    = 10 * time.Second
	DefaultTimeout     = 30 * time.Second
	DefaultMethod      = http.MethodGet
	DefaultWorkers     = 10
	DefaultMaxWorkers  = math.MaxUint64
	DefaultMaxBody     = int64(-1)
	DefaultConnections = 10000
)

// PerformanceOptions 核心压测控制参数
type PerformanceOptions struct {
	// Rate 每秒请求数 (QPS)
	Rate int
	// Duration 压测持续的总时间
	Duration time.Duration
	// Timeout 单个 HTTP 请求的超时时间
	Timeout time.Duration
	// Workers 初始启动的并发协程数
	Workers uint64
	// MaxWorkers 允许启动的最大并发协程数
	MaxWorkers uint64
}

// HTTPConfig HTTP 协议相关设置
type HTTPConfig struct {
	// Method HTTP 请求方法 (如 GET, POST)
	Method string
	// Body 请求体内容（用于 POST/PUT）
	Body []byte
	// MaxBody 读取响应体的最大限制
	MaxBody int64
	// Header 自定义 HTTP 请求头
	Header http.Header
	// KeepAlive 是否使用持久连接
	KeepAlive bool
	// Connections 每个主机的最大闲置连接数
	Connections int
	// HTTP2 是否强制使用 HTTP/2
	HTTP2 bool
}

// NetworkConfig 网络连接与安全设置
type NetworkConfig struct {
	// LocalAddr 指定发起请求的本地源 IP 地址
	LocalAddr net.IPAddr
	// Resolvers 自定义 DNS 解析器地址列表
	Resolvers []string
	// InsecureSkipVerify 是否跳过 TLS 证书验证
	InsecureSkipVerify bool
	// CACertificatePool 自定义 CA 证书池
	CACertificatePool *x509.CertPool
	// TLSCertificates 客户端使用的 TLS 证书
	TLSCertificates []tls.Certificate
}

// OutputConfig 统计数据与文件导出配置
type OutputConfig struct {
	// Buckets 延迟统计的分布区间（用于直方图）
	Buckets []time.Duration
}

// Options 定义了压测的所有可选配置参数，按功能模块划分为：
// 1. Performance (性能控制: QPS, 持续时间等)
// 2. HTTP (协议配置: Method, Header, Body 等)
// 3. Network (网络与安全: DNS, TLS 等)
type Options struct {
	Performance PerformanceOptions
	HTTP        HTTPConfig
	Network     NetworkConfig
	Attacker    backedAttacker
	output      OutputConfig
}

// backedAttacker 是对底层 vegeta 攻击者的抽象接口
type backedAttacker interface {
	Attack(vegeta.Targeter, vegeta.Pacer, time.Duration, string) <-chan *vegeta.Result
	Stop() bool
}

// NewAttacker 创建并初始化一个压测引擎实例。
// 它会验证 target URL，设置默认值，并配置 DNS/TLS。
func NewAttacker(storage Writer, target string, opts *Options) (Attacker, error) {
	if target == "" {
		return nil, net.InvalidAddrError("target is required")
	}

	if opts == nil {
		opts = &Options{}
	}

	validateOptions(opts)

	// 如果指定了自定义解析器，则覆盖默认 DNS 解析
	if len(opts.Network.Resolvers) > 0 {
		net.DefaultResolver = NewResolver(opts.Network.Resolvers)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.Network.InsecureSkipVerify,
		Certificates:       opts.Network.TLSCertificates,
		RootCAs:            opts.Network.CACertificatePool,
	}

	// 初始化底层的 Vegeta 引擎
	if opts.Attacker == nil {
		opts.Attacker = vegeta.NewAttacker(
			vegeta.Timeout(opts.Performance.Timeout),
			vegeta.Workers(opts.Performance.Workers),
			vegeta.MaxWorkers(opts.Performance.MaxWorkers),
			vegeta.MaxBody(opts.HTTP.MaxBody),
			vegeta.Connections(opts.HTTP.Connections),
			vegeta.KeepAlive(opts.HTTP.KeepAlive),
			vegeta.HTTP2(opts.HTTP.HTTP2),
			vegeta.LocalAddr(opts.Network.LocalAddr),
			vegeta.TLSConfig(tlsConfig),
		)
	}

	return &attacker{
		target:      target,
		performance: opts.Performance,
		http:        opts.HTTP,
		network:     opts.Network,
		attacker:    opts.Attacker,
		storage:     storage,
	}, nil
}

func validateOptions(opts *Options) {
	if opts.HTTP.Method == "" {
		opts.HTTP.Method = DefaultMethod
	}
	if opts.Performance.Workers == 0 {
		opts.Performance.Workers = DefaultWorkers
	}
	if opts.Performance.MaxWorkers == 0 {
		opts.Performance.MaxWorkers = DefaultMaxWorkers
	}
	if opts.HTTP.MaxBody == 0 {
		opts.HTTP.MaxBody = DefaultMaxBody
	}
	if opts.HTTP.Connections == 0 {
		opts.HTTP.Connections = DefaultConnections
	}
	if opts.Network.LocalAddr.IP == nil {
		opts.Network.LocalAddr = DefaultLocalAddr
	}
}

// Attacker 定义了外部可调用的压测引擎接口
type Attacker interface {
	// Attack 启动压力测试。
	// metricsCh 用于接收实时的统计摘要。
	Attack(ctx context.Context, metricsCh chan *Metrics) error

	// Rate 返回当前配置的 QPS
	Rate() int
	// Duration 返回当前配置的持续时间
	Duration() time.Duration
	// Method 返回当前使用的 HTTP 方法
	Method() string
}

var (
	// DefaultLocalAddr 默认本地地址
	DefaultLocalAddr = net.IPAddr{IP: net.IPv4zero}
)

type attacker struct {
	target      string
	performance PerformanceOptions
	http        HTTPConfig
	network     NetworkConfig
	output      OutputConfig

	attacker backedAttacker
	storage  Writer
}

// --- 核心逻辑模块 ---

// Attack 是压测引擎的核心方法，执行HTTP压力测试并实时处理结果。
//
// 该方法采用流式处理模式，通过channel接收vegeta底层引擎产生的每个请求结果，
// 1. storage.Writer: 存储原始数据，供GUI查询历史数据并绘制图表
// 2. metricsCh: 推送给UI，实时更新统计图表
//
// 参数:
//   - ctx context.Context: 外部取消信号（如用户按Ctrl+C），用于优雅退出
//   - metricsCh chan *Metrics: 向UI层推送实时统计数据的通道
//
// 返回:
//   - error: 执行过程中的错误（如导出器初始化失败）
//
// 工作流程:
//  1. 初始化阶段：配置速率、目标、统计器和导出器
//  2. 执行阶段：启动vegeta引擎，循环处理每个请求结果
//  3. 收尾阶段：关闭统计器，计算最终统计
func (a *attacker) Attack(ctx context.Context, metricsCh chan *Metrics) error {
	// ========== 阶段1：初始化配置 ==========

	// 配置压测速率：Freq表示每秒请求数，Per表示时间单位（1秒）
	// 例如：Rate{Freq: 50, Per: time.Second} 表示每秒发送50个请求
	rate := vegeta.Rate{Freq: a.performance.Rate, Per: time.Second}

	// 创建静态目标（Targeter）：定义HTTP请求的所有参数
	// vegeta会根据这个配置重复发送请求，直到达到指定的持续时间
	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: a.http.Method, // HTTP方法：GET/POST/PUT等
		URL:    a.target,      // 目标URL：如 http://example.com/api
		Body:   a.http.Body,   // 请求体：用于POST/PUT请求
		Header: a.http.Header, // 请求头：如 Content-Type, Authorization
	})

	// 初始化vegeta统计器：用于实时计算延迟百分位、成功率等指标
	metrics := &vegeta.Metrics{}

	// 如果配置了延迟分桶，则初始化直方图
	// 直方图用于统计延迟分布情况，例如：有多少请求的延迟在0-10ms，10-50ms等
	if len(a.output.Buckets) > 0 {
		metrics.Histogram = &vegeta.Histogram{Buckets: a.output.Buckets}
	}

	// ========== 阶段2：主循环 - 执行压测 ==========

	// 调用底层vegeta引擎的Attack方法，启动压测
	// 返回值是一个channel，会持续产生每个HTTP请求的结果
	// channel关闭表示压测完成（达到持续时间或手动停止）
	for res := range a.attacker.Attack(targeter, rate, a.performance.Duration, "main") {
		// 使用select监听取消信号，实现可控的优雅退出
		select {
		case <-ctx.Done():
			// 外部上下文被取消（如用户按Ctrl+C），停止攻击
			// Stop() 会立即停止底层引擎，不再产生新的请求
			a.attacker.Stop()

			// 优雅退出，不返回错误（用户主动取消不是错误）
			return nil

		default:
			// ========== 处理单个请求结果 ==========

			// 1. 累加统计：将单次结果加入vegeta统计器
			// 统计器会自动计算累积的P50、P90、P95、P99等百分位
			metrics.Add(res)

			// 2. 转换为用于UI展示的Metrics格式
			m := newMetrics(metrics)

			// 3. 存储原始数据：插入storage模块，供GUI查询历史数据
			// GUI可以基于这些数据绘制实时图表（延迟趋势、状态码分布等）
			err := a.storage.Insert(&Result{
				Code:      res.Code,        // HTTP状态码
				Timestamp: res.Timestamp,   // 请求时间戳
				Latency:   res.Latency,     // 请求延迟
				P50:       m.Latencies.P50, // 当前P50延迟
				P90:       m.Latencies.P90, // 当前P90延迟
				P95:       m.Latencies.P95, // 当前P95延迟
				P99:       m.Latencies.P99, // 当前P99延迟
			})
			if err != nil {
				// 存储失败，记录日志并继续处理下一个结果
				// 不中断压测，因为存储失败不应该影响压测执行
				log.Printf("failed to insert results")
				continue
			}

			// 4. 推送给UI：通过channel发送聚合统计数据
			// UI层会接收这些数据并实时更新图表（延迟曲线、成功率等）
			metricsCh <- m
		}
	}

	// ========== 阶段4：收尾工作 ==========

	// 关闭统计器：计算最终统计值
	// Close() 会触发最终计算，确保所有百分位值都是准确的
	metrics.Close()

	// 生成最终统计结果（包含完整的P50/P90/P95/P99、成功率等）
	finalMetrics := newMetrics(metrics)

	// 向UI发送最终统计结果，确保UI显示最终数据
	metricsCh <- finalMetrics

	// 压测完成，返回nil表示成功
	return nil
}

func (a *attacker) Rate() int {
	return a.performance.Rate
}

func (a *attacker) Duration() time.Duration {
	return a.performance.Duration
}

func (a *attacker) Method() string {
	return a.http.Method
}
