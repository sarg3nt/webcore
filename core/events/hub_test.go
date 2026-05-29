package events

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	evtLogs    = "logs.updated"
	evtMetrics = "metrics.updated"
)

// newTestHub returns a Hub backed by a buffered slog handler so tests can
// inspect emitted warnings.
func newTestHub(t *testing.T) (*Hub, *bytes.Buffer, *sync.Mutex) {
	t.Helper()
	var buf bytes.Buffer
	var mu sync.Mutex
	handler := slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug})
	return NewHub(slog.New(handler)), &buf, &mu
}

// lockedWriter serialises writes from goroutines that share the slog handler
// so the buffer doesn't tear under -race.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func countLines(buf *bytes.Buffer, mu *sync.Mutex, substr string) int {
	mu.Lock()
	defer mu.Unlock()
	return strings.Count(buf.String(), substr)
}

func TestSubscriberBufferDefault(t *testing.T) {
	hub, _, _ := newTestHub(t)
	hub.Start()
	defer hub.Stop()
	sub := hub.Subscribe("sub-1", "")
	if got := cap(sub.Events); got != DefaultBufferSize {
		t.Fatalf("subscriber channel cap = %d, want %d", got, DefaultBufferSize)
	}
}

func TestWithBufferSize(t *testing.T) {
	hub := NewHub(nil, WithBufferSize(8))
	hub.Start()
	defer hub.Stop()
	sub := hub.Subscribe("s", "")
	if got := cap(sub.Events); got != 8 {
		t.Fatalf("cap = %d, want 8", got)
	}
}

func TestPublishDeliversAndSetsTimestamp(t *testing.T) {
	hub, _, _ := newTestHub(t)
	hub.Start()
	defer hub.Stop()
	sub := hub.Subscribe("s", "")
	hub.Publish(Event{Type: evtLogs})
	select {
	case ev := <-sub.Events:
		if ev.Type != evtLogs {
			t.Errorf("got type %q", ev.Type)
		}
		if ev.Timestamp.IsZero() {
			t.Error("Publish should stamp Timestamp")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestTopicFilter(t *testing.T) {
	hub, _, _ := newTestHub(t)
	hub.Start()
	defer hub.Stop()

	all := hub.Subscribe("all", "")        // wildcard
	srvA := hub.Subscribe("a", "server-a") // filtered

	hub.Publish(Event{Type: evtLogs, Topic: "server-b"})

	// Wildcard subscriber gets it.
	select {
	case ev := <-all.Events:
		if ev.Topic != "server-b" {
			t.Errorf("wildcard got topic %q", ev.Topic)
		}
	case <-time.After(time.Second):
		t.Fatal("wildcard subscriber missed event")
	}

	// server-a subscriber must NOT get a server-b event.
	select {
	case ev := <-srvA.Events:
		t.Fatalf("filtered subscriber should not receive server-b event, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
		// expected: nothing delivered
	}

	// An untopic'd event reaches the filtered subscriber (wildcard-on-empty).
	hub.Publish(Event{Type: evtMetrics})
	select {
	case ev := <-srvA.Events:
		if ev.Type != evtMetrics {
			t.Errorf("got %q", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("filtered subscriber should receive untopic'd event")
	}
}

func TestSubscriberCountAndUnsubscribe(t *testing.T) {
	hub, _, _ := newTestHub(t)
	hub.Start()
	defer hub.Stop()
	a := hub.Subscribe("a", "")
	hub.Subscribe("b", "")
	// Subscribe returns once run() receives the registration, which is before
	// the map insert completes under the lock — so poll rather than reading the
	// count immediately.
	if !waitForCount(hub, 2, time.Second) {
		t.Fatalf("count = %d, want 2", hub.SubscriberCount())
	}
	hub.Unsubscribe(a)
	if !waitForCount(hub, 1, time.Second) {
		t.Fatalf("count after unsubscribe = %d, want 1", hub.SubscriberCount())
	}
}

// waitForCount polls SubscriberCount until it equals want or timeout elapses.
// Registration/unregistration are processed asynchronously by run(), so the
// count is eventually-consistent with Subscribe/Unsubscribe returning.
func waitForCount(hub *Hub, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if hub.SubscriberCount() == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return hub.SubscriberCount() == want
}

func TestRecordDropFirstDropLogsImmediately(t *testing.T) {
	hub, buf, mu := newTestHub(t)
	t0 := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	hub.recordDropAt("sub-1", evtLogs, t0)
	if got := countLines(buf, mu, "subscriber event channel full"); got != 1 {
		t.Fatalf("expected 1 warning on first drop, got %d. log=%q", got, buf.String())
	}
}

func TestRecordDropCoalescesWithinWindow(t *testing.T) {
	hub, buf, mu := newTestHub(t)
	t0 := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	hub.recordDropAt("sub-1", evtLogs, t0)
	for i := 1; i <= 99; i++ {
		hub.recordDropAt("sub-1", evtLogs, t0.Add(time.Duration(i)*time.Millisecond))
	}
	if got := countLines(buf, mu, "subscriber event channel full"); got != 1 {
		t.Fatalf("expected 1 coalesced warning, got %d. log=%q", got, buf.String())
	}
}

func TestRecordDropEmitsAfterIntervalWithCount(t *testing.T) {
	hub, buf, mu := newTestHub(t)
	t0 := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	hub.recordDropAt("sub-1", evtLogs, t0)
	for i := 1; i <= 49; i++ {
		hub.recordDropAt("sub-1", evtLogs, t0.Add(time.Duration(i)*time.Millisecond))
	}
	hub.recordDropAt("sub-1", evtLogs, t0.Add(dropLogInterval+time.Millisecond))
	if got := countLines(buf, mu, "subscriber event channel full"); got != 2 {
		t.Fatalf("expected 2 warnings after crossing interval, got %d. log=%q", got, buf.String())
	}
	if !strings.Contains(buf.String(), "dropped=50") {
		t.Fatalf("expected coalesced count of 50 in second warning, log=%q", buf.String())
	}
}

func TestRecordDropPerSubscriberPerTypeIndependent(t *testing.T) {
	hub, buf, mu := newTestHub(t)
	t0 := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	hub.recordDropAt("sub-1", evtLogs, t0)
	hub.recordDropAt("sub-1", evtMetrics, t0)
	hub.recordDropAt("sub-2", evtLogs, t0)
	if got := countLines(buf, mu, "subscriber event channel full"); got != 3 {
		t.Fatalf("expected 3 independent first-drop warnings, got %d. log=%q", got, buf.String())
	}
}

func TestCleanupDropTrackerRemovesSubscriberEntries(t *testing.T) {
	hub, _, _ := newTestHub(t)
	t0 := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	hub.recordDropAt("sub-1", evtLogs, t0)
	hub.recordDropAt("sub-1", evtMetrics, t0)
	hub.recordDropAt("sub-2", evtLogs, t0)
	if got := len(hub.subscriberDrops); got != 3 {
		t.Fatalf("expected 3 tracker entries, got %d", got)
	}
	hub.cleanupDropTracker("sub-1")
	if got := len(hub.subscriberDrops); got != 1 {
		t.Fatalf("expected 1 tracker entry after cleanup, got %d", got)
	}
	if _, ok := hub.subscriberDrops[dropKey{subID: "sub-2", eventType: evtLogs}]; !ok {
		t.Fatal("sub-2 entry should have survived cleanup of sub-1")
	}
}

func TestSlowSubscriberDropsAreCoalesced(t *testing.T) {
	hub, buf, mu := newTestHub(t)
	hub.Start()
	defer hub.Stop()

	sub := hub.Subscribe("slow-sub", "")
	_ = sub // never drained

	for i := 0; i < DefaultBufferSize*3; i++ {
		hub.Publish(Event{Type: evtLogs})
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countLines(buf, mu, "subscriber event channel full") >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := countLines(buf, mu, "subscriber event channel full")
	if got == 0 {
		t.Fatalf("expected at least one drop warning under burst, got none. log=%q", buf.String())
	}
	if got > 5 {
		t.Fatalf("expected coalesced warning(s), got %d (no throttling?). log=%q", got, buf.String())
	}
}

func TestMarshalEvent(t *testing.T) {
	b, err := MarshalEvent(Event{Type: evtLogs, Topic: "t"})
	if err != nil {
		t.Fatalf("MarshalEvent: %v", err)
	}
	if !strings.Contains(string(b), `"type":"logs.updated"`) {
		t.Errorf("marshaled = %s", b)
	}
}
