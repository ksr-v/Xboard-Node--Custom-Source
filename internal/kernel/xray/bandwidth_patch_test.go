package xray

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	dispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	core "github.com/xtls/xray-core/core"
	featurebandwidth "github.com/xtls/xray-core/features/bandwidth"
	"golang.org/x/time/rate"
)

type bandwidthSink struct{ count atomic.Int64 }

func (w *bandwidthSink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.count.Add(int64(mb.Len()))
	buf.ReleaseMulti(mb)
	return nil
}

func TestMaintainedCoreLargeWriterWaitReleasesWhenLimitRemoved(t *testing.T) {
	lim := rate.NewLimiter(1, 1)
	lim.Allow()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sink := &bandwidthSink{}
	w := &dispatcher.RateLimitWriter{Writer: sink, Limiter: lim, Context: ctx}
	done := make(chan error, 1)
	go func() { done <- w.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat([]byte{1}, 3*1024*1024))) }()
	select {
	case err := <-done:
		t.Fatalf("must wait before the limit is removed, got %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	lim.SetLimit(rate.Inf)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("existing writer did not observe unlimited update")
	}
	if sink.count.Load() != 3*1024*1024 {
		t.Fatal("writer truncated large MultiBuffer")
	}
}

func TestMaintainedCoreWriterCancellationReleasesBuffers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &dispatcher.RateLimitWriter{Writer: &bandwidthSink{}, Limiter: rate.NewLimiter(1, 1), Context: ctx}
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, []byte("controlled"))); err != context.Canceled {
		t.Fatalf("got %v", err)
	}
}

func TestXrayUUIDAndEmailShareTheSameLiveBandwidthBucket(t *testing.T) {
	inst := new(core.Instance)
	manager := featurebandwidth.New()
	if err := inst.AddFeature(manager); err != nil {
		t.Fatal(err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.users = []model.UserSpec{{ID: 1, UUID: "controlled-user", SpeedLimit: 0}}
	shared := rate.NewLimiter(rate.Inf, 65536)
	x.SetSpeedLimitFunc(func(string) *rate.Limiter { return shared })
	if manager.GetUserLimiter("controlled-user") != shared || manager.GetUserLimiter(userEmail(1)) != shared {
		t.Fatal("authenticated UUID and protocol email must share the live bucket even when currently unlimited")
	}
}
