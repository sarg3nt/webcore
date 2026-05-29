// Package transport adapts a core/events Hub to network transports. It
// currently provides a Server-Sent Events (SSE) HTTP handler; a WebSocket
// transport can join it later behind the same Hub.
package transport

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sarg3nt/web-core/core/events"
)

// SSEHandler streams events from a Hub to a single HTTP client as SSE. Build
// one with NewSSE and mount its ServeHTTP on a route; each request opens its
// own subscription for the life of the connection.
type SSEHandler struct {
	hub        *events.Hub
	logger     *slog.Logger
	topicParam string
	keepalive  time.Duration
	newID      func() string
}

// Option configures an SSEHandler.
type Option func(*SSEHandler)

// WithLogger attaches a logger (default: slog.Default()).
func WithLogger(l *slog.Logger) Option {
	return func(h *SSEHandler) {
		if l != nil {
			h.logger = l
		}
	}
}

// WithTopicParam names a query parameter whose value scopes the subscription
// to a Hub topic (e.g. WithTopicParam("server") subscribes to ?server=web-1).
// When unset, or the parameter is absent, the client receives all events.
func WithTopicParam(name string) Option {
	return func(h *SSEHandler) { h.topicParam = name }
}

// WithKeepalive sets the comment-ping interval that keeps proxies and browsers
// from closing an idle connection (default 15s).
func WithKeepalive(d time.Duration) Option {
	return func(h *SSEHandler) {
		if d > 0 {
			h.keepalive = d
		}
	}
}

// WithIDFunc overrides the per-connection subscriber ID generator.
func WithIDFunc(fn func() string) Option {
	return func(h *SSEHandler) {
		if fn != nil {
			h.newID = fn
		}
	}
}

// NewSSE builds an SSE handler over hub.
func NewSSE(hub *events.Hub, opts ...Option) *SSEHandler {
	h := &SSEHandler{
		hub:       hub,
		logger:    slog.Default(),
		keepalive: 15 * time.Second,
		newID:     randomID,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read never fails on supported platforms; fall back to a
		// time-based id rather than panic in a request path.
		return fmt.Sprintf("sub-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// ServeHTTP opens an SSE stream. It blocks until the client disconnects, the
// subscription channel closes (hub stopped), or the request context is done.
func (h *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.hub == nil {
		http.Error(w, "events not available", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	var topic string
	if h.topicParam != "" {
		topic = r.URL.Query().Get(h.topicParam)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)

	id := h.newID()
	sub := h.hub.Subscribe(id, topic)
	defer h.hub.Unsubscribe(sub)

	// Greet the client so it can confirm the stream is live and learn its id.
	h.writeEvent(w, flusher, events.Event{
		Type:      "connected",
		Timestamp: time.Now(),
		Data:      map[string]any{"subscriber_id": id},
	})

	keepalive := time.NewTicker(h.keepalive)
	defer keepalive.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			h.logger.Debug("SSE client disconnected", "subscriber_id", id)
			return
		case event, ok := <-sub.Events:
			if !ok {
				return // hub stopped / subscription closed
			}
			h.writeEvent(w, flusher, event)
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// writeEvent serializes one event as an SSE frame: an `event:` line carrying
// the type and a `data:` line carrying the JSON payload.
func (h *SSEHandler) writeEvent(w http.ResponseWriter, flusher http.Flusher, event events.Event) {
	data, err := events.MarshalEvent(event)
	if err != nil {
		h.logger.Error("failed to marshal SSE event", "error", err)
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\n", event.Type)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}
