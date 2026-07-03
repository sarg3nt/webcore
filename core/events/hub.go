// Package events provides an in-process publish/subscribe hub for real-time
// event distribution, typically fanned out to browsers over SSE (see
// core/transport).
//
// The hub is domain-agnostic: an Event carries a free-form Type string, an
// optional Topic used for filtering, and an arbitrary Data map. Apps define
// their own event-type constants and typed Publish helpers on top of Publish.
//
// Topic filtering follows a wildcard-on-empty rule: a subscriber with an empty
// Topic receives every event; an event with an empty Topic is delivered to
// every subscriber. A non-empty subscriber Topic only filters out events whose
// (non-empty) Topic differs.
package events

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

// Event is a single broadcastable event.
type Event struct {
	// Type is a free-form event type, e.g. "config.changed". Apps define their
	// own constants.
	Type string `json:"type"`
	// Topic optionally scopes the event to a subset of subscribers (e.g. a
	// server ID, tenant, or channel name). Empty means "all subscribers".
	Topic string `json:"topic,omitempty"`
	// Timestamp is set automatically by Publish when zero.
	Timestamp time.Time `json:"timestamp"`
	// Data is an arbitrary JSON-serializable payload.
	Data map[string]any `json:"data,omitempty"`
}

// Subscriber is a registered consumer of events. Read from Events; the channel
// is closed when the subscriber is unregistered or the hub stops.
type Subscriber struct {
	ID     string
	Topic  string // optional filter; empty receives all events
	Events chan Event
}

// DefaultBufferSize is the per-subscriber channel capacity when not overridden.
// Sized to absorb bursts of high-frequency events without dropping; a consumer
// that stays behind for the full window will drop (with a coalesced warning).
const DefaultBufferSize = 500

// dropLogInterval is the minimum gap between consecutive "channel full"
// warnings for the same (subscriber, type) pair. Drops still happen at the
// same rate; only the log output is coalesced.
const dropLogInterval = 10 * time.Second

type dropKey struct {
	subID     string
	eventType string
}

type dropAggregator struct {
	count      int64
	firstSeen  time.Time
	lastLogged time.Time
}

// Hub manages event distribution to subscribers. Create with NewHub, call
// Start once, and Stop to shut down.
type Hub struct {
	subscribers map[string]*Subscriber
	mu          sync.RWMutex
	logger      *slog.Logger
	bufferSize  int
	broadcast   chan Event
	register    chan *Subscriber
	unregister  chan *Subscriber
	done        chan struct{}
	stopOnce    sync.Once
	// subscriberDrops is owned by run() and must not be touched elsewhere.
	subscriberDrops map[dropKey]*dropAggregator
}

// Option configures a Hub.
type Option func(*Hub)

// WithBufferSize overrides the per-subscriber channel capacity.
func WithBufferSize(n int) Option {
	return func(h *Hub) {
		if n > 0 {
			h.bufferSize = n
		}
	}
}

// NewHub creates a new event hub. A nil logger defaults to slog.Default().
func NewHub(logger *slog.Logger, opts ...Option) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	h := &Hub{
		subscribers:     make(map[string]*Subscriber),
		logger:          logger,
		bufferSize:      DefaultBufferSize,
		broadcast:       make(chan Event, 100),
		register:        make(chan *Subscriber),
		unregister:      make(chan *Subscriber),
		done:            make(chan struct{}),
		subscriberDrops: make(map[dropKey]*dropAggregator),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Start begins processing events in a background goroutine.
func (h *Hub) Start() { go h.run() }

// Stop gracefully shuts down the hub and closes all subscriber channels.
// Safe to call more than once (e.g. from both a signal handler and a defer).
func (h *Hub) Stop() { h.stopOnce.Do(func() { close(h.done) }) }

func (h *Hub) run() {
	for {
		select {
		case <-h.done:
			h.mu.Lock()
			for _, sub := range h.subscribers {
				close(sub.Events)
			}
			h.subscribers = make(map[string]*Subscriber)
			h.mu.Unlock()
			return

		case sub := <-h.register:
			h.mu.Lock()
			h.subscribers[sub.ID] = sub
			h.mu.Unlock()
			h.logger.Debug("subscriber registered", "id", sub.ID, "topic", sub.Topic)

		case sub := <-h.unregister:
			h.mu.Lock()
			if _, exists := h.subscribers[sub.ID]; exists {
				close(sub.Events)
				delete(h.subscribers, sub.ID)
				h.logger.Debug("subscriber unregistered", "id", sub.ID)
			}
			h.mu.Unlock()
			h.cleanupDropTracker(sub.ID)

		case event := <-h.broadcast:
			h.mu.RLock()
			for _, sub := range h.subscribers {
				// Wildcard-on-empty topic filter.
				if sub.Topic != "" && event.Topic != "" && sub.Topic != event.Topic {
					continue
				}
				select {
				case sub.Events <- event:
				default:
					h.recordDrop(sub.ID, event.Type)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Subscribe registers a subscriber with the given id and optional topic filter.
// Blocks until the hub's run loop accepts the registration. If the hub has
// been stopped, the returned subscriber's Events channel is already closed —
// consumers that range/receive on it observe !ok immediately and exit, rather
// than the caller hanging on a registration nothing will ever drain.
func (h *Hub) Subscribe(id, topic string) *Subscriber {
	sub := &Subscriber{
		ID:     id,
		Topic:  topic,
		Events: make(chan Event, h.bufferSize),
	}
	select {
	case h.register <- sub:
	case <-h.done:
		close(sub.Events)
	}
	return sub
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(sub *Subscriber) {
	select {
	case h.unregister <- sub:
	case <-h.done:
	}
}

// Publish broadcasts an event to all matching subscribers. Sets Timestamp when
// zero. Non-blocking: if the hub's broadcast buffer is full the event is
// dropped with a warning.
func (h *Hub) Publish(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	select {
	case h.broadcast <- event:
	case <-h.done:
	default:
		h.logger.Warn("broadcast channel full, dropping event", "event_type", event.Type)
	}
}

// SubscriberCount returns the number of active subscribers.
func (h *Hub) SubscriberCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subscribers)
}

// recordDrop accounts for one dropped event and emits a coalesced warning at
// most once per dropLogInterval per (subscriber, type). Called only from run().
func (h *Hub) recordDrop(subID, eventType string) {
	h.recordDropAt(subID, eventType, time.Now())
}

// recordDropAt is the testable form of recordDrop with an injectable clock.
func (h *Hub) recordDropAt(subID, eventType string, now time.Time) {
	key := dropKey{subID: subID, eventType: eventType}
	agg, ok := h.subscriberDrops[key]
	if !ok {
		agg = &dropAggregator{firstSeen: now}
		h.subscriberDrops[key] = agg
	}
	agg.count++

	if now.Sub(agg.lastLogged) < dropLogInterval {
		return
	}
	h.logger.Warn("subscriber event channel full, dropping event(s)",
		"subscriber_id", subID,
		"event_type", eventType,
		"dropped", agg.count,
		"window", now.Sub(agg.firstSeen).Round(time.Millisecond))
	agg.lastLogged = now
	agg.firstSeen = now
	agg.count = 0
}

// cleanupDropTracker removes drop-aggregator entries for an unsubscribed
// subscriber so the map doesn't grow with churn. Called only from run().
func (h *Hub) cleanupDropTracker(subID string) {
	for k := range h.subscriberDrops {
		if k.subID == subID {
			delete(h.subscriberDrops, k)
		}
	}
}

// MarshalEvent converts an event to JSON (e.g. for an SSE data: line).
func MarshalEvent(event Event) ([]byte, error) {
	return json.Marshal(event)
}
