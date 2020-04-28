package trace

import (
	"context"
	"go.opentelemetry.io/otel/api/global"
	"go.opentelemetry.io/otel/api/trace"
	"go.opentelemetry.io/otel/exporters/otlp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func NewOTLPExporterAndProvider(endpoint string) (*otlp.Exporter, *sdktrace.Provider, error) {
	exporter, err := otlp.NewExporter(
		otlp.WithInsecure(),
		otlp.WithAddress(endpoint),
	)
	if err != nil {
		return nil, nil, err
	}
	provider, err := sdktrace.NewProvider(
		sdktrace.WithConfig(sdktrace.Config{DefaultSampler: sdktrace.AlwaysSample()}),
		sdktrace.WithBatcher(exporter, // add following two options to ensure flush
			sdktrace.WithScheduleDelayMillis(5),
			sdktrace.WithMaxExportBatchSize(10),
		))
	if err != nil {
		return nil, nil, err
	}
	global.SetTraceProvider(provider)
	return exporter, provider, nil
}

func TraceProvider() trace.Provider {
	return global.TraceProvider()
}

type TraceContext struct {
	Ctx    *context.Context
	Tracer trace.Tracer
}

func NewTraceContext(tracer string) *TraceContext {
	ctx := context.Background()
	traceContext := &TraceContext{
		Ctx:    &ctx,
		Tracer: TraceProvider().Tracer(tracer),
	}
	return traceContext
}

func (tc *TraceContext) StartSpan(spanName string) trace.Span {
	ctx, span := tc.Tracer.Start(*tc.Ctx, spanName)
	tc.Ctx = &ctx
	return span
}