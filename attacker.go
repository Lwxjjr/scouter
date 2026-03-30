package scouter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// Options 定义了压测的所有可选配置参数，按功能模块划分为：
// 1. Performance (性能控制: QPS, 持续时间等)
// 2. HTTP (协议配置: Method, Header, Body 等)
// 3. Network (网络与安全: DNS, TLS 等)
type Options struct {
	Performance PerformanceOptions
	HTTP        HTTPConfig
	Network     NetworkConfig
	Attacker    backedAttacker
}

// backedAttacker 是对底层 vegeta 攻击者的抽象接口
type backedAttacker interface {
	Attack(vegeta.Targeter, vegeta.Pacer, time.Duration, string) <-chan *vegeta.Result
	Stop()
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

	attacker backedAttacker
	storage  Writer
}

// Attack 实现 Attacker 接口
func (a *attacker) Attack(ctx context.Context, metricsCh chan *Metrics) error {
	return nil
}

// Rate 实现 Attacker 接口
func (a *attacker) Rate() int {
	return a.performance.Rate
}

// Duration 实现 Attacker 接口
func (a *attacker) Duration() time.Duration {
	return a.performance.Duration
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

// NewResolver 创建一个新的 DNS 解析器
func NewResolver(resolvers []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, "udp", resolvers[0])
		},
	}
}
