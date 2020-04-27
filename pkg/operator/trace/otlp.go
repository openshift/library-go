package trace

import (
	"go.opentelemetry.io/otel/api/global"
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
