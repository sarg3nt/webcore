// Single shared EventSource for a server's SSE endpoint.
//
// Browsers cap HTTP/1.1 connections per origin (Chrome: 6). An SSE stream
// holds that slot for its entire lifetime. Opening one EventSource per feature
// (toasts, charts, a live table) and overlapping them across page navigations
// quickly exhausts the pool, after which every subsequent request — navigation,
// AJAX, asset fetch — stalls until the browser GCs the orphaned streams.
//
// This module collapses every SSE consumer onto ONE EventSource. Consumers
// register a handler for a named event via WebCore.events.on(name, cb); the
// shared stream dispatches each named event to all registered handlers. The
// stream is opened lazily on the first subscription and torn down on pagehide
// so a navigation never carries an open stream into the next page's budget.
//
// Pair with core/transport SSEHandler, whose frames are
// `event: <type>\n data: <json>\n\n`, so `name` here is the event Type and
// `ev.data` is the JSON payload string (call JSON.parse on it).
//
// Usage:
//   WebCore.events.configure({ url: "/api/events?server=web-1" });
//   const off = WebCore.events.on("metrics.updated", (ev) => {
//     const data = JSON.parse(ev.data);
//     ...
//   });
//   // later: off();
(function () {
	"use strict";

	var WebCore = (window.WebCore = window.WebCore || {});
	if (WebCore.events) return;

	var streamURL = "/api/events";
	var handlers = Object.create(null);
	var es = null;

	function ensureOpen() {
		if (es) return;
		if (typeof EventSource === "undefined") return;
		es = new EventSource(streamURL);
		es.onerror = function () {
			// The browser auto-retries transient drops. On a hard close
			// (server restart) drop the dead handle so the next subscription
			// reopens cleanly rather than keeping a closed stream around.
			if (es && es.readyState === EventSource.CLOSED) {
				es = null;
			}
		};
		// Re-attach existing handlers to the freshly opened stream.
		for (var name in handlers) {
			es.addEventListener(name, handlers[name].dispatch);
		}
	}

	// configure sets the stream URL. Call before the first on() subscription;
	// if a stream is already open it is closed so the new URL takes effect on
	// the next subscription.
	function configure(opts) {
		if (opts && typeof opts.url === "string" && opts.url) {
			streamURL = opts.url;
			if (es) {
				es.close();
				es = null;
			}
		}
	}

	// on registers cb for the named event and returns an unsubscribe function.
	function on(name, cb) {
		var slot = handlers[name];
		if (!slot) {
			slot = handlers[name] = {
				callbacks: new Set(),
				dispatch: function (ev) {
					slot.callbacks.forEach(function (fn) {
						try {
							fn(ev);
						} catch (e) {
							// One bad subscriber must not break the others.
						}
					});
				},
			};
			ensureOpen();
			if (es) es.addEventListener(name, slot.dispatch);
		} else {
			ensureOpen();
		}
		slot.callbacks.add(cb);
		return function unsubscribe() {
			slot.callbacks.delete(cb);
		};
	}

	function close() {
		if (es) {
			es.close();
			es = null;
		}
	}

	// Close on pagehide so the stream isn't held open while the next page is
	// also trying to open one — that overlap is what stacks up connections.
	window.addEventListener("pagehide", close);

	WebCore.events = { configure: configure, on: on, close: close };
})();
