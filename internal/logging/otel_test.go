package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestOTelHandler_WithValidSpan(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := NewOTelHandler(inner)
	logger := slog.New(handler)

	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     false,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "test message")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}

	if got := entry["trace_id"]; got != traceID.String() {
		t.Errorf("trace_id = %q, want %q", got, traceID.String())
	}
	if got := entry["span_id"]; got != spanID.String() {
		t.Errorf("span_id = %q, want %q", got, spanID.String())
	}
	if got := entry["trace_flags"]; got != "01" {
		t.Errorf("trace_flags = %q, want %q", got, "01")
	}
}

func TestOTelHandler_WithoutSpan(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := NewOTelHandler(inner)
	logger := slog.New(handler)

	logger.InfoContext(context.Background(), "no span")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}

	if _, ok := entry["trace_id"]; ok {
		t.Error("trace_id should not be present without a span")
	}
	if _, ok := entry["span_id"]; ok {
		t.Error("span_id should not be present without a span")
	}
}

func TestOTelHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := NewOTelHandler(inner)
	logger := slog.New(handler).With("key", "value")

	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "with attrs")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}

	if got := entry["key"]; got != "value" {
		t.Errorf("key = %q, want %q", got, "value")
	}
	if got := entry["trace_id"]; got != traceID.String() {
		t.Errorf("trace_id = %q, want %q", got, traceID.String())
	}
}

func TestOTelHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := NewOTelHandler(inner)
	logger := slog.New(handler).WithGroup("grp")

	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "grouped", "field", "val")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}

	// With slog groups, record attrs (including injected trace fields) are
	// nested inside the group. Verify they exist there.
	grp, ok := entry["grp"].(map[string]any)
	if !ok {
		t.Fatal("expected 'grp' group in log entry")
	}
	if got := grp["trace_id"]; got != traceID.String() {
		t.Errorf("grp.trace_id = %q, want %q", got, traceID.String())
	}
	if got := grp["field"]; got != "val" {
		t.Errorf("grp.field = %q, want %q", got, "val")
	}
}
