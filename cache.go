package scouter

import (
	"time"

	"github.com/Lwxjjr/tcore"
)

type Cache interface {
	Writer
	Reader
}

type Writer interface {
	Insert(result *Result) error
}

type Reader interface {
	Select(metric string, start, end time.Time) ([]float64, error)
}

type Result struct {
	Code      uint16        // 状态码
	Latency   time.Duration // 延迟，指的是该次 HTTP 请求从发送到接收完成所花费的真实时间
	Timestamp time.Time
}

func NewCache(duration time.Duration) (Cache, error) {
	s, err := tcore.NewStorage(
		tcore.WithDuration(duration),
	)
	if err != nil {
		return nil, err
	}
	return &cache{
		storage: s,
	}, nil
}

type cache struct {
	storage tcore.Storage
}

func (c *cache) Insert(result *Result) error {
	return nil
}

func (c *cache) Select(metric string, start, end time.Time) ([]float64, error) {
	return nil, nil
}
