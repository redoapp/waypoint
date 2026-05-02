package metrics

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// initTracing creates and configures a TracerProvider with OTLP export.
func initTracing(ctx context.Context, cfg Config) (*sdktrace.TracerProvider, error) {
	exporter, err := newTraceExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create trace exporter: %w", err)
	}

	sampler := sdktrace.TraceIDRatioBased(cfg.TracingSampleRate)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sampler)),
	)

	return tp, nil
}

func newTraceExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	switch cfg.Protocol {
	case "", "http":
		return otlptracehttp.New(ctx,
			otlptracehttp.WithEndpointURL(cfg.Endpoint),
		)
	case "grpc":
		return otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpointURL(cfg.Endpoint),
		)
	default:
		return nil, fmt.Errorf("unsupported trace protocol %q (use \"http\" or \"grpc\")", cfg.Protocol)
	}
}
