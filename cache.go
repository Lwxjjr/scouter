package scouter

import (
	"errors"
	"time"

	"github.com/Lwxjjr/tcore"
)

const (
	LatencyMetricName = "latency"
	P50MetricName     = "p50"
	P90MetricName     = "p90"
	P95MetricName     = "p95"
	P99MetricName     = "p99"
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
	P50       time.Duration
	P90       time.Duration
	P95       time.Duration
	P99       time.Duration
}

func NewCache(duration time.Duration) (Cache, error) {
	s, err := tcore.NewStorage(
		tcore.WithDuration(duration),
	)
	if err != nil {
		return nil, err
	}
	return &cache{storage: s}, nil
}

type cache struct {
	storage tcore.Storage
}

func (c *cache) Insert(result *Result) error {
	// Convert timestamp into unix time in nanoseconds.
	timestamp := result.Timestamp.UnixNano()
	rows := []tcore.Row{
		{
			Metric: LatencyMetricName,
			DataPoint: tcore.DataPoint{
				Timestamp: timestamp,
				Value:     float64(result.Latency.Milliseconds()),
			},
		},
		{
			Metric: P50MetricName,
			DataPoint: tcore.DataPoint{
				Timestamp: timestamp,
				Value:     float64(result.P50.Milliseconds()),
			},
		},
		{
			Metric: P90MetricName,
			DataPoint: tcore.DataPoint{
				Timestamp: timestamp,
				Value:     float64(result.P90.Milliseconds()),
			},
		},
		{
			Metric: P95MetricName,
			DataPoint: tcore.DataPoint{
				Timestamp: timestamp,
				Value:     float64(result.P95.Milliseconds()),
			},
		},
		{
			Metric: P99MetricName,
			DataPoint: tcore.DataPoint{
				Timestamp: timestamp,
				Value:     float64(result.P99.Milliseconds()),
			},
		},
	}
	return c.storage.InsertRows(rows)
}

func (c *cache) Select(metric string, start, end time.Time) ([]float64, error) {
	points, err := c.storage.Select(metric, nil, start.UnixNano(), end.UnixNano())
	if errors.Is(err, tcore.ErrNoDataPoints) {
		return []float64{}, nil
	}
	if err != nil {
		return nil, err
	}
	values := make([]float64, len(points))
	for i := range points {
		values[i] = points[i].Value
	}
	return values, nil
}
