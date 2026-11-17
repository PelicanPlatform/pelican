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

// Package tracingtest installs an in-memory span exporter for unit tests and
// provides helpers for asserting on the recorded spans.
//
// Tracing state is process-wide, so tests that call Setup or Disabled must not
// run in parallel with each other.
package tracingtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/pelicanplatform/pelican/tracing"
)

type options struct {
	defaultService      tracing.Service
	samplePercentage    int
	trustRemoteSampling bool
}

// Option adjusts Setup.
type Option func(*options)

// WithDefaultService sets the service for spans with no local parent.  The
// default is tracing.ServiceClient.
func WithDefaultService(svc tracing.Service) Option {
	return func(o *options) { o.defaultService = svc }
}

// WithSamplePercentage sets the sampling percentage.  The default is 100.
func WithSamplePercentage(pct int) Option {
	return func(o *options) { o.samplePercentage = pct }
}

// WithTrustRemoteSampling makes spans with a remote parent follow the
// parent's sampled flag.  The default is false, as in production.
func WithTrustRemoteSampling(trust bool) Option {
	return func(o *options) { o.trustRemoteSampling = trust }
}

// Setup enables tracing with an in-memory exporter and synchronous export,
// so a span is visible in the exporter as soon as it ends.  Sampling is 100%
// and the default service is tracing.ServiceClient unless overridden.
//
// On cleanup the configuration Setup installed is shut down, which leaves
// tracing disabled (the normal state of a test process) unless something else
// has replaced it since.  Setup does not nest: a second Setup, or an enabled
// tracing.Init, replaces the first, and the first exporter's recorded spans
// are then cleared.  Read the exporter before the test's cleanup runs.
//
// Note that tracing.Init with Tracing.Enabled unset leaves this state alone,
// so a test federation can be started under Setup.
func Setup(t testing.TB, opts ...Option) *tracetest.InMemoryExporter {
	t.Helper()
	o := options{
		defaultService:   tracing.ServiceClient,
		samplePercentage: 100,
	}
	for _, opt := range opts {
		opt(&o)
	}

	exporter := tracetest.NewInMemoryExporter()
	stop, err := tracing.Configure(tracing.Options{
		Exporter:            exporter,
		Synchronous:         true,
		SampleRatio:         float64(o.samplePercentage) / 100,
		TrustRemoteSampling: o.trustRemoteSampling,
		DefaultService:      o.defaultService,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = stop(context.Background())
	})
	return exporter
}

// Disabled guarantees that tracing is off for the rest of the test, and again
// at cleanup.
func Disabled(t testing.TB) {
	t.Helper()
	require.NoError(t, tracing.Shutdown(context.Background()))
	require.False(t, tracing.Enabled())
	t.Cleanup(func() {
		_ = tracing.Shutdown(context.Background())
	})
}

// SpansNamed returns the finished spans with the given name, in the order they
// ended.
func SpansNamed(exporter *tracetest.InMemoryExporter, name string) []tracetest.SpanStub {
	var found []tracetest.SpanStub
	for _, s := range exporter.GetSpans() {
		if s.Name == name {
			found = append(found, s)
		}
	}
	return found
}

// RequireSpan returns the single finished span with the given name, failing
// the test if there is not exactly one.
func RequireSpan(t testing.TB, exporter *tracetest.InMemoryExporter, name string) tracetest.SpanStub {
	t.Helper()
	found := SpansNamed(exporter, name)
	require.Lenf(t, found, 1, "expected exactly one span named %q; recorded spans: %v", name, Names(exporter))
	return found[0]
}

// Names returns the names of the finished spans, in the order they ended.
func Names(exporter *tracetest.InMemoryExporter) []string {
	spans := exporter.GetSpans()
	names := make([]string, 0, len(spans))
	for _, s := range spans {
		names = append(names, s.Name)
	}
	return names
}

// Attributes returns a span's attributes as a map from key to Go value
// (string, bool, int64, float64 or a slice of those).
func Attributes(span tracetest.SpanStub) map[string]any {
	return attributeMap(span.Attributes)
}

// ResourceAttributes returns the attributes of the span's resource.
func ResourceAttributes(span tracetest.SpanStub) map[string]any {
	if span.Resource == nil {
		return map[string]any{}
	}
	return attributeMap(span.Resource.Attributes())
}

// ServiceName returns the service.name the span was reported under.
func ServiceName(span tracetest.SpanStub) string {
	if span.Resource == nil {
		return ""
	}
	v, _ := span.Resource.Set().Value("service.name")
	return v.AsString()
}

func attributeMap(kvs []attribute.KeyValue) map[string]any {
	m := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value.AsInterface()
	}
	return m
}

// RequireParent fails the test unless child is a direct child of parent in
// the same trace.
func RequireParent(t testing.TB, parent, child tracetest.SpanStub) {
	t.Helper()
	require.Equal(t, parent.SpanContext.TraceID(), child.SpanContext.TraceID(),
		"span %q is not in the same trace as %q", child.Name, parent.Name)
	require.Equal(t, parent.SpanContext.SpanID(), child.Parent.SpanID(),
		"span %q is not a child of %q", child.Name, parent.Name)
}

// RequireNoSpans fails the test if any span was recorded.
func RequireNoSpans(t testing.TB, exporter *tracetest.InMemoryExporter) {
	t.Helper()
	require.Empty(t, exporter.GetSpans(), "expected no spans; recorded: %v", Names(exporter))
}
