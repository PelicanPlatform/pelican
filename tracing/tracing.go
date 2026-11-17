/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

// Package tracing is Pelican's single entry point to OpenTelemetry tracing.
//
// Tracing is off unless Tracing.Enabled is set.  While it is off every
// function here reduces to a nil check: Start returns a no-op span, Client and
// Transport return their argument, and no header is added to any request.
//
// The package keeps its tracer providers and propagator private.  It never
// sets the global OpenTelemetry tracer provider or propagator, because other
// libraries in the build create spans against the global provider and must
// stay silent.  The one global it touches is the OpenTelemetry error handler
// (see installErrorHandler).
package tracing

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// Service is the service.name a span is reported under.
type Service string

const (
	ServiceClient   Service = "pelican-client"
	ServiceDirector Service = "pelican-director"
	ServiceOrigin   Service = "pelican-origin"
	ServiceCache    Service = "pelican-cache"
	ServiceServer   Service = "pelican-server" // a multi-module process, for spans with no parent
)

// instrumentationName is the instrumentation scope recorded on every span.
const instrumentationName = "github.com/pelicanplatform/pelican"

// replacedShutdownTimeout bounds the background flush of a configuration that
// Configure replaced.
const replacedShutdownTimeout = 5 * time.Second

// Options configures tracing directly, bypassing the Tracing.* parameters.
// Init builds Options from the parameters; tests use it (through
// tracingtest.Setup) to install an in-memory exporter.
type Options struct {
	// Exporter receives finished spans.  Required.
	Exporter sdktrace.SpanExporter
	// Synchronous exports each span as it ends (a simple span processor)
	// instead of batching.  Use it only in tests.
	Synchronous bool
	// SampleRatio is the fraction of traces recorded, clamped to [0, 1].
	SampleRatio float64
	// TrustRemoteSampling makes spans with a remote parent follow the
	// parent's sampled flag instead of recomputing the decision.
	TrustRemoteSampling bool
	// DefaultService names spans that have no local parent.  Empty means
	// ServiceServer.
	DefaultService Service
}

// state is one complete tracing configuration.  A nil state means tracing is
// disabled.  A state is immutable apart from its lazily filled provider maps.
type state struct {
	defaultService Service
	sampler        sdktrace.Sampler
	processor      sdktrace.SpanProcessor
	propagator     propagation.TextMapPropagator
	// deferred is non-nil when no endpoint was known at Init and spans are
	// held until OfferEndpoint supplies one.
	deferred *deferredExporter
	// baseResource holds the attributes shared by every service (host,
	// version, OTEL_RESOURCE_ATTRIBUTES); service.name is merged in per
	// provider.
	baseResource *resource.Resource

	mu        sync.RWMutex
	providers map[Service]*sdktrace.TracerProvider
	tracers   map[Service]trace.Tracer
	services  map[*sdktrace.TracerProvider]Service
}

var (
	// current is the active configuration, or nil when tracing is disabled.
	current atomic.Pointer[state]
	// configMu serialises Configure and Shutdown so that a replaced state is
	// always shut down exactly once.
	configMu sync.Mutex

	noopSpan trace.Span = noop.Span{}

	errorHandlerOnce sync.Once
)

// Init reads the Tracing.* parameters and, if tracing is enabled, installs
// the exporter and samplers.  defaultService names spans that have no parent
// span; only a client process (ServiceClient) is expected to start any.
//
// When Tracing.Enabled is false Init does nothing and returns a nil stop.
// Otherwise stop flushes and shuts down the configuration this call installed
// and nothing else: if a later Init or Configure has replaced it, stop leaves
// the replacement running.
//
// Calling Init again with tracing enabled replaces the previous configuration,
// which is then flushed and shut down in the background.
func Init(ctx context.Context, defaultService Service) (stop func(context.Context) error, err error) {
	if !param.Tracing_Enabled.GetBool() {
		return nil, nil
	}

	pct := param.Tracing_SamplePercentage.GetInt()
	if pct < 0 {
		pct = 0
	} else if pct > 100 {
		pct = 100
	}

	var exporter sdktrace.SpanExporter
	if endpoint := param.Tracing_Endpoint.GetString(); endpoint != "" {
		exporter, err = newOTLPExporter(ctx, endpoint)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid %s", param.Tracing_Endpoint.GetName())
		}
		log.Debugf("Tracing: exporting spans to %s", endpoint)
	} else if otlpEndpointFromEnv() {
		// The OTLP exporter reads OTEL_EXPORTER_OTLP_[TRACES_]ENDPOINT itself.
		exporter, err = newOTLPExporter(ctx, "")
		if err != nil {
			return nil, errors.Wrap(err, "failed to create OTLP exporter from the OTEL_EXPORTER_OTLP_* environment")
		}
		log.Debug("Tracing: exporting spans to the endpoint in the OTEL_EXPORTER_OTLP_* environment")
	} else {
		exporter = newDeferredExporter(newOTLPExporter)
		log.Debug("Tracing: no endpoint configured yet; holding spans until the federation advertises one")
	}

	stop, err = Configure(Options{
		Exporter:            exporter,
		SampleRatio:         float64(pct) / 100,
		TrustRemoteSampling: param.Tracing_TrustRemoteSampling.GetBool(),
		DefaultService:      defaultService,
	})
	if err != nil {
		return nil, err
	}

	// A locally configured federation endpoint needs no discovery.
	OfferEndpoint(param.Federation_TracingEndpoint.GetString())
	return stop, nil
}

// otlpEndpointFromEnv reports whether the standard OTLP environment variables
// name an endpoint.
func otlpEndpointFromEnv() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

// Configure enables tracing with explicit options, replacing (and shutting
// down) any previous configuration.  Most callers want Init; Configure exists
// for tests and for callers that build their own exporter.  The returned stop
// shuts down this configuration only (see Init).
func Configure(opts Options) (stop func(context.Context) error, err error) {
	if opts.Exporter == nil {
		return nil, errors.New("tracing: an exporter is required")
	}
	ratio := opts.SampleRatio
	if ratio < 0 {
		ratio = 0
	} else if ratio > 1 {
		ratio = 1
	}
	svc := opts.DefaultService
	if svc == "" {
		svc = ServiceServer
	}

	root := sdktrace.TraceIDRatioBased(ratio)
	var sampler sdktrace.Sampler
	if opts.TrustRemoteSampling {
		sampler = sdktrace.ParentBased(root)
	} else {
		// A remote parent's sampled flag is ignored and the decision is
		// recomputed from the trace ID, so a client cannot force a server to
		// record.  Local parents are still followed.
		sampler = sdktrace.ParentBased(root,
			sdktrace.WithRemoteParentSampled(root),
			sdktrace.WithRemoteParentNotSampled(root))
	}

	var processor sdktrace.SpanProcessor
	if opts.Synchronous {
		processor = sdktrace.NewSimpleSpanProcessor(opts.Exporter)
	} else {
		processor = sdktrace.NewBatchSpanProcessor(opts.Exporter)
	}

	deferred, _ := opts.Exporter.(*deferredExporter)

	st := &state{
		defaultService: svc,
		sampler:        sampler,
		processor:      processor,
		propagator:     propagation.TraceContext{},
		deferred:       deferred,
		baseResource:   baseResource(),
		providers:      make(map[Service]*sdktrace.TracerProvider),
		tracers:        make(map[Service]trace.Tracer),
		services:       make(map[*sdktrace.TracerProvider]Service),
	}

	installErrorHandler()

	configMu.Lock()
	defer configMu.Unlock()
	if old := current.Swap(st); old != nil {
		// The old configuration's spans are flushed in the background so that
		// reconfiguring never waits on a collector.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), replacedShutdownTimeout)
			defer cancel()
			if err := old.shutdown(ctx); err != nil {
				log.Debugf("Tracing: error shutting down the previous configuration: %v", err)
			}
		}()
	}
	return func(ctx context.Context) error {
		configMu.Lock()
		mine := current.CompareAndSwap(st, nil)
		configMu.Unlock()
		if !mine {
			// Already replaced (and shut down by its replacement) or stopped.
			return nil
		}
		return st.shutdown(ctx)
	}, nil
}

// installErrorHandler routes OpenTelemetry's internal errors (for example a
// failed export to an unreachable collector) to logrus at debug level.  The
// default handler prints every error to stderr.
//
// This is the one OpenTelemetry global Pelican sets.  It is installed only
// once tracing is enabled, so processes that do not trace keep the default.
func installErrorHandler() {
	errorHandlerOnce.Do(func() {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			if err != nil {
				log.Debugf("Tracing: %s", Scrub(err.Error()))
			}
		}))
	})
}

// baseResource builds the resource attributes shared by every service.
func baseResource() *resource.Resource {
	host := param.Server_Hostname.GetString()
	if host == "" {
		host, _ = os.Hostname()
	}
	attrs := []attribute.KeyValue{
		attribute.String("service.version", config.GetVersion()),
	}
	if host != "" {
		attrs = append(attrs,
			attribute.String("host.name", host),
			attribute.String("service.instance.id", host))
	}
	ours := resource.NewSchemaless(attrs...)

	// OTEL_RESOURCE_ATTRIBUTES (and OTEL_SERVICE_NAME, which state.tracer
	// overrides per service) supply extras; our attributes win on conflict.
	env, err := resource.New(context.Background(), resource.WithFromEnv(), resource.WithTelemetrySDK())
	if err != nil {
		log.Debugf("Tracing: ignoring invalid resource attributes from the environment: %v", err)
	}
	if env == nil {
		return ours
	}
	merged, err := resource.Merge(env, ours)
	if err != nil {
		log.Debugf("Tracing: failed to merge resource attributes from the environment: %v", err)
		return ours
	}
	return merged
}

// tracer returns the tracer for svc, creating its provider on first use.
func (st *state) tracer(svc Service) trace.Tracer {
	st.mu.RLock()
	t, ok := st.tracers[svc]
	st.mu.RUnlock()
	if ok {
		return t
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if t, ok = st.tracers[svc]; ok {
		return t
	}
	res, err := resource.Merge(st.baseResource,
		resource.NewSchemaless(attribute.String("service.name", string(svc))))
	if err != nil {
		res = resource.NewSchemaless(attribute.String("service.name", string(svc)))
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(st.sampler),
		sdktrace.WithSpanProcessor(st.processor),
	)
	t = tp.Tracer(instrumentationName, trace.WithInstrumentationVersion(config.GetVersion()))
	st.providers[svc] = tp
	st.tracers[svc] = t
	st.services[tp] = svc
	return t
}

// serviceOf reports which service a provider belongs to, if it is one of
// this state's providers.
func (st *state) serviceOf(tp trace.TracerProvider) (Service, bool) {
	sdkTP, ok := tp.(*sdktrace.TracerProvider)
	if !ok {
		return "", false
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	svc, ok := st.services[sdkTP]
	return svc, ok
}

// shutdown flushes and stops the shared span processor, which in turn shuts
// down the exporter.  The providers share that processor, so it is shut down
// directly rather than once per provider.
func (st *state) shutdown(ctx context.Context) error {
	return st.processor.Shutdown(ctx)
}

// Shutdown flushes pending spans and stops the exporter, leaving tracing
// disabled.  It gives up after the context's deadline.  It is safe to call
// when tracing was never initialised.
func Shutdown(ctx context.Context) error {
	configMu.Lock()
	st := current.Swap(nil)
	configMu.Unlock()
	if st == nil {
		return nil
	}
	return st.shutdown(ctx)
}

// Flush exports pending spans without stopping the exporter.  It gives up
// after the context's deadline.  It is safe to call when tracing is disabled.
func Flush(ctx context.Context) error {
	st := current.Load()
	if st == nil {
		return nil
	}
	err := st.processor.ForceFlush(ctx)
	if st.deferred != nil {
		// Spans held before the endpoint was known are exported in the
		// background; a caller about to exit must wait for those too.
		if waitErr := st.deferred.waitFlushed(ctx); err == nil {
			err = waitErr
		}
	}
	return err
}

// Enabled reports whether spans are being created.
func Enabled() bool {
	return current.Load() != nil
}

// DefaultService returns the service that spans with no parent are reported
// under, or "" when tracing is disabled.  It is ServiceClient in a client
// process, which is the only kind of process that starts traces of its own;
// servers only continue traces that requests bring to them.
func DefaultService() Service {
	st := current.Load()
	if st == nil {
		return ""
	}
	return st.defaultService
}

// Start starts a span.  It inherits the service of the span already in ctx;
// with no span in ctx (or only a remote one) it uses the process default.
//
// When tracing is disabled it returns ctx unchanged and a no-op span.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	st := current.Load()
	if st == nil {
		return ctx, noopSpan
	}
	svc := st.defaultService
	if parent := trace.SpanFromContext(ctx); parent.SpanContext().IsValid() && !parent.SpanContext().IsRemote() {
		if s, ok := st.serviceOf(parent.TracerProvider()); ok {
			svc = s
		}
	}
	return st.tracer(svc).Start(ctx, name, opts...)
}

// StartChild starts a span only if ctx already holds one, as its child.  With
// no span in ctx it returns ctx unchanged and a no-op span, so the caller
// never starts a trace of its own.  Use it for work that is traced only as
// part of a request that is itself traced.
func StartChild(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, noopSpan
	}
	return Start(ctx, name, opts...)
}

// NoopSpan returns a span that records nothing, for callers that need a span
// value on a path that is not traced.
func NoopSpan() trace.Span {
	return noopSpan
}

// StartWithService starts a span reported under svc regardless of the span
// already in ctx (which still becomes its parent).
//
// When tracing is disabled it returns ctx unchanged and a no-op span.
func StartWithService(ctx context.Context, svc Service, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	st := current.Load()
	if st == nil {
		return ctx, noopSpan
	}
	return st.tracer(svc).Start(ctx, name, opts...)
}

// CarrySpan returns dst with the span from src attached.  Deadlines,
// cancellation and other values of src are not carried.  When src holds no
// valid span, dst is returned unchanged.
func CarrySpan(dst, src context.Context) context.Context {
	span := trace.SpanFromContext(src)
	if !span.SpanContext().IsValid() {
		return dst
	}
	return trace.ContextWithSpan(dst, span)
}

// LogFields returns trace_id and span_id for the span in ctx, or nil when ctx
// holds no span that is being recorded.  A trace that was sampled out gets no
// fields: its ID would point at a trace that was never exported.
func LogFields(ctx context.Context) log.Fields {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() || !sc.IsSampled() {
		return nil
	}
	return log.Fields{
		"trace_id": sc.TraceID().String(),
		"span_id":  sc.SpanID().String(),
	}
}

// WithLogFields returns entry with LogFields(ctx) added, or entry itself when
// there are none.
func WithLogFields(entry *log.Entry, ctx context.Context) *log.Entry {
	if fields := LogFields(ctx); fields != nil {
		return entry.WithFields(fields)
	}
	return entry
}

// TraceID returns the hex trace ID of the span in ctx, or "" when ctx holds no
// valid span.
func TraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}
