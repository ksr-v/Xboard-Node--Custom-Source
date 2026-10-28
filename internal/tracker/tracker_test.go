package tracker

import (
	"reflect"
	"sync"
	"testing"
)

func TestProcess_InitialTraffic(t *testing.T) {
	tr := New()
	cumTraffic := map[int][2]int64{
		1: {100, 200},
		2: {50, 80},
	}
	aliveIPs := map[int]map[string]bool{
		1: {"1.1.1.1": true},
		2: {"2.2.2.2": true},
	}
	tr.Process(cumTraffic, aliveIPs, 2)

	flushed := tr.FlushTraffic()
	if flushed[1] != [2]int64{100, 200} {
		t.Errorf("user 1 traffic: got %v", flushed[1])
	}
	if flushed[2] != [2]int64{50, 80} {
		t.Errorf("user 2 traffic: got %v", flushed[2])
	}
}

func TestProcess_DeltaCalculation(t *testing.T) {
	tr := New()

	// First tick
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	// Second tick — counters advanced
	tr.Process(map[int][2]int64{1: {300, 500}}, nil, 1)

	flushed := tr.FlushTraffic()
	// Total: first tick 100/200 + delta 200/300 = 300/500
	if flushed[1] != [2]int64{300, 500} {
		t.Errorf("accumulated: got %v, want [300,500]", flushed[1])
	}
}

func TestProcess_CounterReset(t *testing.T) {
	tr := New()

	// First tick with high counters
	tr.Process(map[int][2]int64{1: {1000, 2000}}, nil, 1)
	tr.FlushTraffic() // clear accumulator

	// Counter reset (new value < old value) — treat as fresh
	tr.Process(map[int][2]int64{1: {50, 80}}, nil, 1)

	flushed := tr.FlushTraffic()
	if flushed[1] != [2]int64{50, 80} {
		t.Errorf("counter reset: got %v, want [50,80]", flushed[1])
	}
}

func TestProcess_UserDisappears(t *testing.T) {
	tr := New()

	// Tick 1: user present
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	// Tick 2: user gone
	tr.Process(map[int][2]int64{}, nil, 0)

	// Tick 3: user reappears — should count full bytes (treated as new)
	tr.Process(map[int][2]int64{1: {50, 30}}, nil, 1)

	flushed := tr.FlushTraffic()
	// First tick: 100/200, tick 2: 0, tick 3: 50/30 = total 150/230
	if flushed[1] != [2]int64{150, 230} {
		t.Errorf("after disappear: got %v, want [150,230]", flushed[1])
	}
}

func TestProcess_ZeroTraffic(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{}, nil, 0)

	if tr.HasTraffic() {
		t.Error("expected no traffic for empty input")
	}
}

func TestFlushTraffic(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{
		1: {100, 200},
		2: {50, 80},
	}, nil, 2)

	flushed := tr.FlushTraffic()
	if flushed[1] != [2]int64{100, 200} {
		t.Errorf("flushed user 1: got %v", flushed[1])
	}
	if flushed[2] != [2]int64{50, 80} {
		t.Errorf("flushed user 2: got %v", flushed[2])
	}

	// After flush, should be empty
	if tr.HasTraffic() {
		t.Error("expected no traffic after flush")
	}
	flushed2 := tr.FlushTraffic()
	if len(flushed2) != 0 {
		t.Errorf("expected empty after second flush, got %v", flushed2)
	}
}

func TestRestoreTraffic(t *testing.T) {
	tr := New()
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)

	flushed := tr.FlushTraffic()
	tr.RestoreTraffic(flushed)

	if !tr.HasTraffic() {
		t.Error("expected traffic after restore")
	}

	restored := tr.FlushTraffic()
	if restored[1] != [2]int64{100, 200} {
		t.Errorf("restored: got %v", restored[1])
	}
}

func TestRestoreTraffic_Additive(t *testing.T) {
	tr := New()

	// Two ticks accumulate
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	tr.Process(map[int][2]int64{1: {200, 400}}, nil, 1)

	// Flush and restore
	first := tr.FlushTraffic()
	tr.RestoreTraffic(first)

	// Generate additional traffic
	tr.Process(map[int][2]int64{1: {250, 500}}, nil, 1)

	final := tr.FlushTraffic()
	// Restored: 200/400 (initial 100/200 + delta 100/200) + new delta 50/100 = 250/500
	if final[1][0] != 250 || final[1][1] != 500 {
		t.Errorf("additive restore: got %v", final[1])
	}
}

func TestFlushAliveIPs(t *testing.T) {
	tr := New()
	aliveIPs := map[int]map[string]bool{
		1: {"1.1.1.1": true, "2.2.2.2": true},
		2: {"3.3.3.3": true},
	}
	tr.Process(map[int][2]int64{1: {100, 200}, 2: {30, 40}}, aliveIPs, 3)

	flushed := tr.FlushAliveIPs()
	if len(flushed[1]) != 2 {
		t.Errorf("user 1 IPs: got %d, want 2", len(flushed[1]))
	}
	if len(flushed[2]) != 1 {
		t.Errorf("user 2 IPs: got %d, want 1", len(flushed[2]))
	}

	// Repeated full snapshots renew the panel lease even without new traffic.
	flushed2 := tr.FlushAliveIPs()
	if !reflect.DeepEqual(flushed, flushed2) {
		t.Errorf("heartbeat lost unchanged devices: first %v, second %v", flushed, flushed2)
	}
}

func TestFlushAliveIPs_IndependentRESTAndWSSnapshots(t *testing.T) {
	tr := New()
	tr.Process(nil, map[int]map[string]bool{1: {"1.1.1.1": true}}, 1)
	rest := tr.FlushAliveIPs()
	ws := tr.FlushAliveIPs()
	rest[1][0] = "modified-by-transport"
	delete(rest, 1)
	if !reflect.DeepEqual(ws, map[int][]string{1: {"1.1.1.1"}}) {
		t.Fatalf("transport snapshots alias each other: %v", ws)
	}
	tr.Process(nil, map[int]map[string]bool{1: {"2.2.2.2": true}}, 1)
	if ws[1][0] != "1.1.1.1" {
		t.Fatalf("in-flight snapshot changed during Process: %v", ws)
	}
	if got := tr.FlushAliveIPs(); !reflect.DeepEqual(got, map[int][]string{1: {"2.2.2.2"}}) {
		t.Fatalf("new snapshot did not use latest state: %v", got)
	}
}

func TestFlushAliveIPs_DisconnectProducesExplicitEmptySnapshot(t *testing.T) {
	tr := New()
	tr.Process(nil, map[int]map[string]bool{1: {"1.1.1.1": true}, 2: {"2.2.2.2": true}}, 2)
	tr.FlushAliveIPs()
	tr.Process(nil, map[int]map[string]bool{2: {"2.2.2.2": true}}, 1)
	if got := tr.FlushAliveIPs(); !reflect.DeepEqual(got, map[int][]string{2: {"2.2.2.2"}}) {
		t.Fatalf("closed user's IP remained in full snapshot: %v", got)
	}
	tr.Process(nil, nil, 0)
	for transport := 0; transport < 2; transport++ {
		if got := tr.FlushAliveIPs(); got == nil || len(got) != 0 {
			t.Fatalf("last disconnect must report explicit empty snapshot: %#v", got)
		}
	}
}

func TestFlushAliveIPs_FailedReportRetriesCurrentState(t *testing.T) {
	tr := New()
	tr.Process(nil, map[int]map[string]bool{1: {"1.1.1.1": true}}, 1)
	failedRequest := tr.FlushAliveIPs()
	// A report can fail after its connection has closed. A retry must report
	// current state rather than merge the stale in-flight IP back into it.
	tr.Process(nil, nil, 0)
	if got := tr.FlushAliveIPs(); got == nil || len(got) != 0 {
		t.Fatalf("retry resurrected disconnected device: %v (old %v)", got, failedRequest)
	}
}

func TestFlushAliveIPs_ConcurrentReadersOwnTheirMaps(t *testing.T) {
	tr := New()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			tr.Process(nil, map[int]map[string]bool{1: {"1.1.1.1": true}}, 1)
		}
	}()
	for transport := 0; transport < 2; transport++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				data := tr.FlushAliveIPs()
				data[99] = []string{"transport-local"}
				delete(data, 1)
			}
		}()
	}
	wg.Wait()
	if got := tr.FlushAliveIPs(); !reflect.DeepEqual(got, map[int][]string{1: {"1.1.1.1"}}) {
		t.Fatalf("concurrent transport mutated tracker: %v", got)
	}
}

func TestSpeedTelemetryUsesConfiguredTrackingInterval(t *testing.T) {
	for _, seconds := range []int{1, 5, 10} {
		tr := New()
		tr.SetTrackInterval(seconds)
		tr.Process(map[int][2]int64{1: {int64(1000 * seconds), int64(2000 * seconds)}}, nil, 1)
		// Preserve the existing wire convention: inbound is downloaded bytes,
		// outbound is uploaded bytes. Only the time divisor changes.
		if tr.InboundSpeed() != 2000 || tr.OutboundSpeed() != 1000 {
			t.Fatalf("%d-second tracker reported rates %d/%d; want 2000/1000", seconds, tr.InboundSpeed(), tr.OutboundSpeed())
		}
		traffic := tr.FlushTraffic()
		if traffic[1] != [2]int64{int64(1000 * seconds), int64(2000 * seconds)} {
			t.Fatal("rate display interval changed traffic accounting")
		}
	}
}

func TestFlushAliveIPs_DedupSameIP(t *testing.T) {
	tr := New()
	aliveIPs := map[int]map[string]bool{
		1: {"1.1.1.1": true},
	}
	tr.Process(map[int][2]int64{1: {100, 200}}, aliveIPs, 2)

	flushed := tr.FlushAliveIPs()
	if len(flushed[1]) != 1 {
		t.Errorf("expected 1 IP, got %d", len(flushed[1]))
	}
}

func TestHasTraffic(t *testing.T) {
	tr := New()
	if tr.HasTraffic() {
		t.Error("new tracker should not have traffic")
	}

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	if !tr.HasTraffic() {
		t.Error("should have traffic after process")
	}

	tr.FlushTraffic()
	if tr.HasTraffic() {
		t.Error("should not have traffic after flush")
	}
}

func TestProcess_NoTrafficDelta(t *testing.T) {
	tr := New()

	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	tr.FlushTraffic() // clear

	// Same values — no delta
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	if tr.HasTraffic() {
		t.Error("expected no traffic for zero delta")
	}
}

func TestTrafficAccumulation(t *testing.T) {
	tr := New()

	// Tick 1
	tr.Process(map[int][2]int64{1: {100, 200}}, nil, 1)
	// Tick 2 (cumulative 300, 500 → delta 200, 300)
	tr.Process(map[int][2]int64{1: {300, 500}}, nil, 1)
	// Tick 3 (cumulative 350, 600 → delta 50, 100)
	tr.Process(map[int][2]int64{1: {350, 600}}, nil, 1)

	flushed := tr.FlushTraffic()
	// Total: 100+200+50 = 350 upload, 200+300+100 = 600 download
	if flushed[1] != [2]int64{350, 600} {
		t.Errorf("accumulated: got %v, want [350,600]", flushed[1])
	}
}
