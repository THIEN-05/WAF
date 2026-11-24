package telemetry

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"
)

const TraceSamplingRatio = 0.001

// InitTracing installs the requested low-rate sampler. When endpoint is empty,
// sampled spans are intentionally local and not exported; production should
// set OTEL_EXPORTER_OTLP_ENDPOINT to an OTLP/HTTP collector.
func InitTracing(ctx context.Context, endpoint string) (func(context.Context) error, error) {
	options := []trace.TracerProviderOption{trace.WithSampler(trace.TraceIDRatioBased(TraceSamplingRatio))}
	if strings.TrimSpace(endpoint) != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, errors.New("OTEL_EXPORTER_OTLP_ENDPOINT must be an absolute URL")
		}
		endpointOptions := []otlptracehttp.Option{otlptracehttp.WithEndpoint(parsed.Host)}
		if parsed.Path != "" && parsed.Path != "/" {
			endpointOptions = append(endpointOptions, otlptracehttp.WithURLPath(parsed.Path))
		}
		if parsed.RawQuery != "" {
			return nil, errors.New("OTEL_EXPORTER_OTLP_ENDPOINT cannot contain a query")
		}
		var exporter trace.SpanExporter
		switch parsed.Scheme {
		case "http":
			endpointOptions = append(endpointOptions, otlptracehttp.WithInsecure())
			exporter, err = otlptracehttp.New(ctx, endpointOptions...)
		case "https":
			exporter, err = otlptracehttp.New(ctx, endpointOptions...)
		default:
			return nil, errors.New("OTEL_EXPORTER_OTLP_ENDPOINT scheme must be http or https")
		}
		if err != nil {
			return nil, err
		}
		options = append(options, trace.WithBatcher(exporter, trace.WithBatchTimeout(time.Second)))
	}
	provider := trace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return provider.Shutdown, nil
}
