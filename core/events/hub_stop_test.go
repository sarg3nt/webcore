package events

import (
	"testing"
	"time"
)

// TestSubscribeAfterStopDoesNotBlock guards the shutdown race: an SSE request
// landing after Hub.Stop must not hang its handler goroutine forever on an
// unregistered channel send. The returned subscriber's channel is pre-closed
// so consumers observe !ok and exit.
func TestSubscribeAfterStopDoesNotBlock(t *testing.T) {
	hub := NewHub(nil)
	hub.Start()
	hub.Stop()

	done := make(chan *Subscriber, 1)
	go func() { done <- hub.Subscribe("late", "") }()

	select {
	case sub := <-done:
		select {
		case _, ok := <-sub.Events:
			if ok {
				t.Error("expected closed Events channel on post-Stop subscriber")
			}
		default:
			t.Error("Events channel should be closed (non-blocking !ok receive)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe blocked after Stop — shutdown deadlock regression")
	}
}

// TestStopTwiceSafe guards the double-shutdown path (signal handler + defer).
func TestStopTwiceSafe(t *testing.T) {
	hub := NewHub(nil)
	hub.Start()
	hub.Stop()
	hub.Stop() // must not panic
}
