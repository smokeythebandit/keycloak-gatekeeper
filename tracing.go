package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"contrib.go.opencensus.io/exporter/jaeger"
	"github.com/go-chi/chi"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/trace"
	"go.opencensus.io/trace/propagation"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	datadog "github.com/DataDog/opencensus-go-exporter-datadog"
	spanlog "github.com/oneconcern/keycloak-gatekeeper/internal/log"
)

// Stdlog is a simplified abstraction of the zap.Logger
type Stdlog interface {
	Debug(msg string, fields ...zapcore.Field)
	Info(msg string, fields ...zapcore.Field)
	Warn(msg string, fields ...zapcore.Field)
	Error(msg string, fields ...zapcore.Field)
	Fatal(msg string, fields ...zapcore.Field)
}

// Logger is a standard logger with a decorator
type Logger interface {
	Stdlog
	With(fields ...zapcore.Field) Logger
}

// proxyTracingHandler forwards the request to the opencensus tracing handler
func (r *oauthProxy) proxyTracingMiddleware(next http.Handler) http.Handler {
	if !r.config.EnableTracing {
		return next
	}
	const svc = "gatekeeper"

	switch r.config.TracingExporter {
	case jaegerExporter:
		// set up span exporter
		je, err := jaeger.NewExporter(jaeger.Options{
			AgentEndpoint: os.ExpandEnv(r.config.TracingAgentEndpoint),
			ServiceName:   svc,
		})
		if err != nil {
			r.log.Warn("jaeger trace span exporting disabled", zap.Error(err))
			r.config.EnableTracing = false
			return next
		}
		trace.RegisterExporter(je)
		r.log.Info("jaeger trace span exporting enabled")
	case datadogExporter:
		exporterError := func(err error) {
			r.log.Warn("could not export trace to datadog agent", zap.Error(err))
		}
		service := os.Getenv("DD_SERVICE")
		if service == "" {
			service = svc
		}
		ns := os.Getenv("DD_NAMESPACE")
		// enable trace exporting to datadog agent
		de, err := datadog.NewExporter(datadog.Options{
			Namespace: ns,
			Service:   service,
			TraceAddr: os.ExpandEnv(r.config.TracingAgentEndpoint),
			OnError:   exporterError,
			GlobalTags: map[string]interface{}{
				"env":       os.Getenv("DD_ENV"),
				"version":   os.Getenv("DD_VERSION"),
				"namespace": ns,
			},
		})
		if err != nil {
			r.log.Info("datadog reporting disabled", zap.Error(err))
			r.config.EnableTracing = false
			return next
		}
		trace.RegisterExporter(de)
		r.log.Info("datadog trace span exporting enabled")
	default:
		r.log.Warn("tracing is enabled, but no supported exporter is configured. Tracing disabled")
	}
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	// insert instrumentation middleware
	var propagator propagation.HTTPFormat
	if r.config.TracingExporter == datadogExporter {
		propagator = &httpFormat{HTTPFormat: &b3.HTTPFormat{}}
	} else {
		propagator = &b3.HTTPFormat{}
	}

	instrument1 := func(next http.Handler) http.Handler {
		return &ochttp.Handler{
			Handler:          next,
			Propagation:      propagator,
			IsPublicEndpoint: false,
		}
	}
	instrument2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route := chi.RouteContext(r.Context())
			ochttp.WithRouteTag(next, route.RoutePath).ServeHTTP(w, r)
		})
	}
	return instrument2(instrument1(next))
}

type logger struct {
	Stdlog
}

func (l logger) With(fields ...zap.Field) Logger {
	if zlg, ok := l.Stdlog.(*zap.Logger); ok {
		return logger{Stdlog: zlg.With(fields...)}
	}

	return l
}

// traceSpan creates a child span from the context.
func (r *oauthProxy) traceSpan(ctx context.Context, title string) (context.Context, *trace.Span, Logger) {
	if !r.config.EnableTracing {
		return ctx, nil, logger{Stdlog: r.log}
	}
	newCtx, span := trace.StartSpan(ctx, title)
	return newCtx, span, logger{Stdlog: spanlog.New(r.log, span)}
}

// traceSpanRequest extracts the span from the current context and attaches a new logger to that span, if any.
//
// The returned span may be nil, but a logger is always returned.
func (r *oauthProxy) traceSpanRequest(req *http.Request) (*trace.Span, Logger) {
	if !r.config.EnableTracing {
		return nil, logger{Stdlog: r.log}
	}
	span := trace.FromContext(req.Context())

	if span != nil {
		return span, logger{Stdlog: spanlog.New(r.log, span)}
	}
	return span, logger{Stdlog: r.log}
}

func traceError(span *trace.Span, err error, code int) error {
	var traceCode int32
	switch err {
	case context.Canceled:
		traceCode = trace.StatusCodeCancelled
	case context.DeadlineExceeded:
		traceCode = trace.StatusCodeDeadlineExceeded
	default:
		switch code {
		case http.StatusForbidden:
			traceCode = trace.StatusCodePermissionDenied
		case http.StatusUnauthorized:
			traceCode = trace.StatusCodeUnauthenticated
		case http.StatusNotFound:
			traceCode = trace.StatusCodeNotFound
		case http.StatusBadRequest:
			traceCode = trace.StatusCodeInvalidArgument
		case http.StatusInternalServerError:
			traceCode = trace.StatusCodeInternal
		default:
			traceCode = trace.StatusCodeUnknown
		}
	}
	if err == nil {
		span.SetStatus(trace.Status{
			Code: traceCode,
		})
	} else {
		span.SetStatus(trace.Status{
			Code:    traceCode,
			Message: err.Error(),
		})
	}
	return err
}

func propagateSpan(span *trace.Span, req *http.Request) {
	// B3 span propagation (e.g. Opentracing)
	// NOTE: datadog is supposed to support opentracing headers
	propagation := &b3.HTTPFormat{}
	propagation.SpanContextToRequest(span.SpanContext(), req)

}

type httpFormat struct {
	*b3.HTTPFormat
}

const (
	datadogTraceIDHeader  = "X-Datadog-Trace-Id"
	datadogSpanIDHeader   = "X-Datadog-Parent-Id"
	datadogSamplingHeader = "X-Datadog-Sampling-Priority"
)

// SpanContextFromRequest extracts a B3 or datadog span context from incoming requests.
func (h *httpFormat) SpanContextFromRequest(req *http.Request) (trace.SpanContext, bool) {
	span, ok := h.HTTPFormat.SpanContextFromRequest(req)
	if ok {
		// if we already have B3 headers, pick those
		return span, ok
	}

	// pick datadog tracing headers and convert them to B3 headers
	tid := req.Header.Get(datadogTraceIDHeader)
	sid := req.Header.Get(datadogSpanIDHeader)
	sampling := req.Header.Get(datadogSamplingHeader)
	var s string
	switch sampling {
	case "1", "true":
		s = "1"
	default:
		s = "0"
	}

	btid, _ := strconv.ParseUint(tid, 10, 64)
	bsid, _ := strconv.ParseUint(sid, 10, 64)

	if btid != 0 && bsid != 0 {
		req.Header.Set(b3.TraceIDHeader, fmt.Sprintf("%016x", btid))
		req.Header.Set(b3.SpanIDHeader, fmt.Sprintf("%016x", bsid))
		req.Header.Set(b3.SampledHeader, s)
	}

	return h.HTTPFormat.SpanContextFromRequest(req)
}
