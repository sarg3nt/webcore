package transport

import (
	"bufio"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sarg3nt/web-core/core/events"
)

func newHub(t *testing.T) *events.Hub {
	t.Helper()
	hub := events.NewHub(slog.New(slog.DiscardHandler))
	hub.Start()
	t.Cleanup(hub.Stop)
	return hub
}

// readFrames opens an SSE stream and returns a channel of raw lines plus a
// cancel func to tear the request down.
func openStream(t *testing.T, url string) (<-chan string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("GET stream: %v", err)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		cancel()
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	lines := make(chan string, 64)
	go func() {
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	return lines, cancel
}

// waitFor collects lines until one contains want or the timeout elapses.
func waitFor(t *testing.T, lines <-chan string, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case l := <-lines:
			if strings.Contains(l, want) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func TestSSEConnectAndReceive(t *testing.T) {
	hub := newHub(t)
	srv := httptest.NewServer(NewSSE(hub, WithKeepalive(time.Hour)))
	defer srv.Close()

	lines, cancel := openStream(t, srv.URL)
	defer cancel()

	// The greeting frame announces the stream is live.
	waitFor(t, lines, "event: connected", time.Second)

	// Give the subscription a moment to register, then publish.
	time.Sleep(50 * time.Millisecond)
	hub.Publish(events.Event{Type: "thing.happened", Data: map[string]any{"n": 1}})

	waitFor(t, lines, "event: thing.happened", 2*time.Second)
	waitFor(t, lines, `"n":1`, time.Second)
}

func TestSSETopicFilter(t *testing.T) {
	hub := newHub(t)
	srv := httptest.NewServer(NewSSE(hub, WithTopicParam("server"), WithKeepalive(time.Hour)))
	defer srv.Close()

	lines, cancel := openStream(t, srv.URL+"?server=web-1")
	defer cancel()
	waitFor(t, lines, "event: connected", time.Second)
	time.Sleep(50 * time.Millisecond)

	// Event for a different topic must not arrive; an event for our topic must.
	hub.Publish(events.Event{Type: "other.topic", Topic: "web-2"})
	hub.Publish(events.Event{Type: "our.topic", Topic: "web-1"})

	waitFor(t, lines, "event: our.topic", 2*time.Second)
	// Drain briefly to ensure other.topic never shows up.
	deadline := time.After(200 * time.Millisecond)
	for {
		select {
		case l := <-lines:
			if strings.Contains(l, "other.topic") {
				t.Fatal("received event for a topic we did not subscribe to")
			}
		case <-deadline:
			return
		}
	}
}

func TestSSENilHubReturns503(t *testing.T) {
	srv := httptest.NewServer(NewSSE(nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestSSEKeepalive(t *testing.T) {
	hub := newHub(t)
	srv := httptest.NewServer(NewSSE(hub, WithKeepalive(50*time.Millisecond)))
	defer srv.Close()
	lines, cancel := openStream(t, srv.URL)
	defer cancel()
	waitFor(t, lines, "event: connected", time.Second)
	waitFor(t, lines, ": keepalive", time.Second)
}

func TestSSESubscriberCleanupOnDisconnect(t *testing.T) {
	hub := newHub(t)
	srv := httptest.NewServer(NewSSE(hub, WithKeepalive(time.Hour)))
	defer srv.Close()

	lines, cancel := openStream(t, srv.URL)
	waitFor(t, lines, "event: connected", time.Second)
	time.Sleep(50 * time.Millisecond)
	if got := hub.SubscriberCount(); got != 1 {
		t.Fatalf("subscriber count = %d, want 1", got)
	}

	cancel() // disconnect client
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.SubscriberCount() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscriber not cleaned up after disconnect, count = %d", hub.SubscriberCount())
}
