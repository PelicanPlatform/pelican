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
	"net/url"
	"strings"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/pelicanplatform/pelican/config"
)

// otlpTracesPath is the path the OTLP/HTTP protocol uses for traces.
const otlpTracesPath = "/v1/traces"

// deferredBufferSize bounds the spans a deferredExporter holds while it waits
// for an endpoint.
const deferredBufferSize = 2048

// exporterFactory builds the real exporter once an endpoint is known.
type exporterFactory func(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error)

// tracesURL turns an OTLP/HTTP base URL such as https://collector:4318 into
// the traces URL https://collector:4318/v1/traces.  A URL that already ends
// in /v1/traces is used as given.
func tracesURL(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.Errorf("tracing endpoint %q must be an http or https URL", endpoint)
	}
	if u.Host == "" {
		return nil, errors.Errorf("tracing endpoint %q has no host", endpoint)
	}
	if !strings.HasSuffix(u.Path, otlpTracesPath) {
		u.Path = strings.TrimSuffix(u.Path, "/") + otlpTracesPath
	}
	u.RawPath = ""
	return u, nil
}

// newOTLPExporter creates an OTLP/HTTP exporter.  With an empty endpoint the
// exporter is configured entirely from the OTEL_EXPORTER_OTLP_* environment.
// Creating the exporter opens no connection.
func newOTLPExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	if endpoint == "" {
		return otlptracehttp.New(ctx)
	}
	u, err := tracesURL(endpoint)
	if err != nil {
		return nil, err
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(u.String())}
	if u.Scheme == "https" {
		// Honour TLSSkipVerify and the configured CA, like every other
		// Pelican connection.
		if tr := config.GetTransport(); tr != nil && tr.TLSClientConfig != nil {
			opts = append(opts, otlptracehttp.WithTLSClientConfig(tr.TLSClientConfig.Clone()))
		}
	} else {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	return otlptracehttp.New(ctx, opts...)
}

// deferredExporter holds spans until an endpoint is offered, then hands them
// to a real exporter and forwards everything after that.
//
// While waiting it keeps at most deferredBufferSize spans; once full, newer
// spans are dropped, so the earliest traces of the process survive intact.
// If no endpoint ever arrives, Shutdown drops the buffer and returns at once.
type deferredExporter struct {
	factory exporterFactory

	mu       sync.Mutex
	target   sdktrace.SpanExporter
	buffer   []sdktrace.ReadOnlySpan
	dropped  int
	stopped  bool
	flushing sync.WaitGroup
}

func newDeferredExporter(factory exporterFactory) *deferredExporter {
	return &deferredExporter{factory: factory}
}

// ExportSpans implements sdktrace.SpanExporter.
func (d *deferredExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	d.mu.Lock()
	if target := d.target; target != nil {
		d.mu.Unlock()
		return target.ExportSpans(ctx, spans)
	}
	defer d.mu.Unlock()
	if d.stopped {
		return nil
	}
	room := deferredBufferSize - len(d.buffer)
	if room < len(spans) {
		if room < 0 {
			room = 0
		}
		d.dropped += len(spans) - room
		spans = spans[:room]
	}
	d.buffer = append(d.buffer, spans...)
	return nil
}

// offer installs the real exporter for endpoint if none is installed yet.
// It reports whether the offer was used.  The buffered spans are exported in
// the background so that the caller never waits on the collector.
func (d *deferredExporter) offer(endpoint string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped || d.target != nil {
		return false
	}
	target, err := d.factory(context.Background(), endpoint)
	if err != nil {
		// Debug, not warning: a client offers on every transfer, and the
		// value comes from the federation, not from this process's operator.
		log.Debugf("Tracing: ignoring the federation's tracing endpoint %q: %v", endpoint, err)
		return false
	}
	d.target = target
	buffered := d.buffer
	d.buffer = nil
	if d.dropped > 0 {
		log.Debugf("Tracing: dropped %d spans while waiting for a tracing endpoint", d.dropped)
	}
	if len(buffered) > 0 {
		d.flushing.Add(1)
		go func() {
			defer d.flushing.Done()
			if err := target.ExportSpans(context.Background(), buffered); err != nil {
				log.Debugf("Tracing: failed to export spans held before the endpoint was known: %s", Scrub(err.Error()))
			}
		}()
	}
	return true
}

// Shutdown implements sdktrace.SpanExporter.
func (d *deferredExporter) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.stopped = true
	target := d.target
	d.buffer = nil
	d.mu.Unlock()
	if target == nil {
		return nil
	}

	_ = d.waitFlushed(ctx)
	return target.Shutdown(ctx)
}

// waitFlushed waits, until ctx is done, for the spans that were held before
// the endpoint was known to be handed to the real exporter.  It returns ctx's
// error if that did not finish in time.
func (d *deferredExporter) waitFlushed(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		d.flushing.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// OfferEndpoint supplies the federation-advertised endpoint.  It is used only
// if no endpoint was configured (Tracing.Endpoint or the OTLP environment
// variables) and tracing is enabled, and only the first non-empty usable
// offer counts.  It never blocks on the collector.
func OfferEndpoint(endpoint string) {
	if endpoint == "" {
		return
	}
	st := current.Load()
	if st == nil || st.deferred == nil {
		return
	}
	if st.deferred.offer(endpoint) {
		log.Debugf("Tracing: exporting spans to the federation's tracing endpoint %s", endpoint)
	}
}
