package querylog

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// DefaultQueueSize is how many pending events an Emitter buffers before it
// starts dropping. Sized so a burst from a busy connection rides through
// without stalling the relay.
const DefaultQueueSize = 4096

// DefaultMaxStatementBytes caps how much statement text reaches the log.
const DefaultMaxStatementBytes = 4096

// Counters lets the server hand the Emitter its OTel instruments without the
// querylog package importing internal/metrics (which would pull the proxy's
// dependency graph into a leaf package).
type Counters struct {
	Emitted     func(ctx context.Context, n int64)
	Dropped     func(ctx context.Context, n int64, listener string)
	ParseErrors func(ctx context.Context, n int64, listener string)
}

// Emitter turns Events into slog records on a background goroutine.
//
// The relay must never wait on logging, so Log is a non-blocking send onto a
// bounded queue: if the queue is full the event is dropped and counted rather
// than backing up into the data path. The worker goroutine does the SQL
// parsing, which keeps AST work off the connection's read loop entirely.
type Emitter struct {
	logger   *slog.Logger
	counters Counters

	queue chan *Event

	dropped atomic.Int64
	emitted atomic.Int64

	// mu guards the queue against a send racing with Close. Connections can
	// still be draining when shutdown begins, so Log must stay safe after
	// the Emitter has been closed.
	mu     sync.RWMutex
	closed bool

	closeOnce sync.Once
	done      chan struct{}
}

// NewEmitter starts an Emitter. Call Close to drain and stop it.
func NewEmitter(logger *slog.Logger, queueSize int, counters Counters) *Emitter {
	if queueSize <= 0 {
		queueSize = DefaultQueueSize
	}
	e := &Emitter{
		logger:   logger,
		counters: counters,
		queue:    make(chan *Event, queueSize),
		done:     make(chan struct{}),
	}
	go e.run()
	return e
}

// Log queues an event. It never blocks and never panics on a closed Emitter;
// a dropped event is counted, because losing a log line must not take a
// database connection down with it.
func (e *Emitter) Log(ev *Event) {
	if e == nil || ev == nil || ev.Level <= LevelOff {
		return
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		e.drop(ev)
		return
	}
	select {
	case e.queue <- ev:
	default:
		e.drop(ev)
	}
}

func (e *Emitter) drop(ev *Event) {
	e.dropped.Add(1)
	if e.counters.Dropped != nil {
		e.counters.Dropped(context.Background(), 1, ev.Listener)
	}
}

// Dropped reports how many events were discarded because the queue was full.
func (e *Emitter) Dropped() int64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

// Emitted reports how many events reached the log.
func (e *Emitter) Emitted() int64 {
	if e == nil {
		return 0
	}
	return e.emitted.Load()
}

// Close stops the Emitter after draining whatever is already queued.
func (e *Emitter) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		close(e.queue)
		e.mu.Unlock()

		<-e.done
		if dropped := e.dropped.Load(); dropped > 0 {
			e.logger.Warn("query log events dropped",
				"component", "querylog",
				"dropped", dropped,
				"hint", "queue full; raise queue size or lower the query log level",
			)
		}
	})
}

func (e *Emitter) run() {
	defer close(e.done)
	for ev := range e.queue {
		e.emit(ev)
	}
}

func (e *Emitter) emit(ev *Event) {
	ctx := context.Background()

	// Postgres events arrive as raw SQL; derive their shape here so the
	// parse cost lands on this goroutine rather than the relay's.
	if ev.RawStatement != "" && ev.Op == "" {
		m := Analyze(ev.RawStatement)
		ev.Op = m.Verb
		ev.Kind = m.Kind
		ev.Tables = m.Tables
		ev.WriteTarget = m.WriteTarget
		ev.Fingerprint = m.Fingerprint
		ev.ParseError = m.ParseError
		ev.Statement = StatementText(m, ev.RawStatement, ev.Level)

		if m.ParseError && e.counters.ParseErrors != nil {
			e.counters.ParseErrors(ctx, 1, ev.Listener)
		}
	}

	// Bind parameters are row data; they belong only in a full record.
	if ev.Level < LevelFull {
		ev.Params = nil
	}

	maxBytes := ev.MaxStatementBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxStatementBytes
	}
	e.logger.LogAttrs(ctx, slog.LevelInfo, "query", ev.attrs(maxBytes)...)

	e.emitted.Add(1)
	if e.counters.Emitted != nil {
		e.counters.Emitted(ctx, 1)
	}
}
