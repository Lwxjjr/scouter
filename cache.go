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
	Latency   time.Duration // 延迟
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
