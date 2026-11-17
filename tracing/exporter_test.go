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

package tracing

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTracesURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		wantErr  bool
	}{
		{in: "https://collector.example.org:4318", want: "https://collector.example.org:4318/v1/traces"},
		{in: "https://collector.example.org:4318/", want: "https://collector.example.org:4318/v1/traces"},
		{in: "http://collector:4318/otlp", want: "http://collector:4318/otlp/v1/traces"},
		{in: "http://collector:4318/v1/traces", want: "http://collector:4318/v1/traces"},
		{in: "collector:4318", wantErr: true},
		{in: "ftp://collector", wantErr: true},
		{in: "https://", wantErr: true},
	} {
		got, err := tracesURL(tc.in)
		if tc.wantErr {
			assert.Error(t, err, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, got.String())
	}
}

func TestDeferredExporterBuffer(t *testing.T) {
	stubs := make(tracetest.SpanStubs, deferredBufferSize+10)
	for i := range stubs {
		stubs[i].Name = "s"
	}
	spans := stubs.Snapshots()

	target := tracetest.NewInMemoryExporter()
	var factoryCalls int
	d := newDeferredExporter(func(context.Context, string) (sdktrace.SpanExporter, error) {
		factoryCalls++
		return target, nil
	})
	ctx := context.Background()
	require.NoError(t, d.ExportSpans(ctx, spans[:10]))
	require.NoError(t, d.ExportSpans(ctx, spans[10:]))
	assert.Len(t, d.buffer, deferredBufferSize)
	assert.Equal(t, 10, d.dropped)

	assert.True(t, d.offer("http://collector:4318"))
	assert.False(t, d.offer("http://other:4318"))
	assert.Equal(t, 1, factoryCalls)
	require.Eventually(t, func() bool { return len(target.GetSpans()) == deferredBufferSize }, 5*time.Second, 10*time.Millisecond)

	require.NoError(t, d.ExportSpans(ctx, spans[:1]))
	assert.Len(t, target.GetSpans(), deferredBufferSize+1)

	require.NoError(t, d.Shutdown(ctx))
	assert.False(t, d.offer("http://late:4318"))
}

func TestDeferredExporterShutdownWithoutEndpoint(t *testing.T) {
	d := newDeferredExporter(func(context.Context, string) (sdktrace.SpanExporter, error) {
		t.Fatal("the factory must not be called")
		return nil, nil
	})
	stubs := tracetest.SpanStubs{{Name: "s"}}
	require.NoError(t, d.ExportSpans(context.Background(), stubs.Snapshots()))
	require.NoError(t, d.Shutdown(context.Background()))
	assert.Nil(t, d.buffer)
	assert.False(t, d.offer("http://collector:4318"))
	// Spans after shutdown are dropped silently.
	require.NoError(t, d.ExportSpans(context.Background(), stubs.Snapshots()))
	assert.Nil(t, d.buffer)
}

// gatedExporter is an exporter whose ExportSpans blocks until it is released.
type gatedExporter struct {
	entered  chan struct{}
	release  chan struct{}
	exported atomic.Int32
}

func (g *gatedExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	g.entered <- struct{}{}
	<-g.release
	g.exported.Add(int32(len(spans)))
	return nil
}

func (g *gatedExporter) Shutdown(context.Context) error { return nil }

// Flush must not return success while the spans that were held before the
// endpoint was known are still on their way: a command that exits right
// after Flush would lose them.
func TestFlushWaitsForHeldSpans(t *testing.T) {
	gate := &gatedExporter{entered: make(chan struct{}, 1), release: make(chan struct{})}
	deferred := newDeferredExporter(func(context.Context, string) (sdktrace.SpanExporter, error) {
		return gate, nil
	})
	stop, err := Configure(Options{Exporter: deferred, Synchronous: true, SampleRatio: 1, DefaultService: ServiceClient})
	require.NoError(t, err)
	t.Cleanup(func() { _ = stop(context.Background()) })

	// Held: no endpoint is known yet.
	_, span := Start(context.Background(), "held")
	span.End()

	// The offer hands the held span to the real exporter in the background,
	// where it is now stuck.
	OfferEndpoint("http://collector.invalid:4318")
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the held span was never handed to the exporter")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, Flush(cancelled), context.Canceled,
		"Flush reported success although the held span had not been exported")
	require.Zero(t, gate.exported.Load())

	close(gate.release)
	require.NoError(t, Flush(context.Background()))
	require.EqualValues(t, 1, gate.exported.Load(), "the held span is exported by the time Flush returns")
}
