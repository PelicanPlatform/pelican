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

package client

// Tracing for object downloads (design/opentelemetry/README.md, section 5).
//
// Every helper here is nil-safe: a nil *jobSpan or *tracedOp means "this
// transfer is not being traced", which is the case when tracing is disabled,
// when the trace was sampled out, and for every operation that is not a
// download.  The call sites in the transfer code therefore stay one line each
// and do nothing new when tracing is off.
//
// Only a client process (`object get`, the transfer plugin) starts traces of
// its own.  The client embedded in a server traces a download only as part of
// a trace the server is already recording, that is, when the context handed
// to NewTransferJob holds a span.

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/tracing"
)

// Attribute keys used only by the client.  Keys shared with other services
// live in the tracing package.
const (
	attrClientProject     = attribute.Key("pelican.client.project")
	attrTransferRecursive = attribute.Key("pelican.transfer.recursive")
	attrTransferObjects   = attribute.Key("pelican.transfer.objects")
	attrTransferAttempts  = attribute.Key("pelican.transfer.attempts")
	attrDirectorEndpoint  = attribute.Key("pelican.director.endpoint")
	attrDirectorWithToken = attribute.Key("pelican.director.with_token")

	attrAttemptCandidates      = attribute.Key("pelican.attempt.candidates")
	attrAttemptNumber          = attribute.Key("pelican.attempt.number")
	attrAttemptEndpoint        = attribute.Key("pelican.attempt.endpoint")
	attrAttemptBytes           = attribute.Key("pelican.attempt.bytes")
	attrAttemptCacheAgeS       = attribute.Key("pelican.attempt.cache_age_s")
	attrAttemptServerVersion   = attribute.Key("pelican.attempt.server_version")
	attrAttemptRetryable       = attribute.Key("pelican.attempt.retryable")
	attrAttemptTimeToFirstByte = attribute.Key("pelican.attempt.time_to_first_byte_ms")
)

// Span names.
const (
	spanTransfer       = "client.transfer"
	spanDiscoverFed    = "client.discover_federation"
	spanQueryDirector  = "client.query_director"
	spanAcquireToken   = "client.acquire_token"
	spanStat           = "client.stat"
	spanDownloadObject = "client.download_object"
	spanSortAttempts   = "client.sort_attempts"
	spanAttempt        = "client.attempt"
	spanVerifyChecksum = "client.verify_checksum"
)

// tracingFlushTimeout bounds FlushTracing, so that an unreachable collector
// delays a command's exit by no more than this.
const tracingFlushTimeout = 2 * time.Second

// tracingSpanWait is the part of tracingFlushTimeout that FlushTracing may
// spend waiting for transfer spans to end.  The rest is kept for the export,
// so that one span that never ends cannot cost every finished span its export.
const tracingSpanWait = 1500 * time.Millisecond

// InitTracing starts tracing for a client command (`object get`, the transfer
// plugin) with pelican-client as the default service.  It is a no-op unless
// Tracing.Enabled is set, and a failure is logged rather than returned:
// tracing must never stop a transfer.  Call it after config.InitClient.
func InitTracing(ctx context.Context) {
	// The stop function is not kept: a command flushes with FlushTracing and
	// then exits.
	if _, err := tracing.Init(ctx, tracing.ServiceClient); err != nil {
		log.Warningln("Tracing: could not be initialized; continuing without it:", err)
	}
}

// FlushTracing waits for the client.transfer spans of jobs that are still
// finishing (a job that failed or was cancelled ends its span in the
// background) and then exports every pending span, all within two seconds,
// so that a client command can exit without losing its trace.  It returns at
// once when tracing is disabled.
//
// Only short-lived commands call it.  It waits for every job span in the
// process, so it must not be called while jobs are still being started.
func FlushTracing() {
	ctx, cancel := context.WithTimeout(context.Background(), tracingFlushTimeout)
	defer cancel()
	waitCtx, cancelWait := context.WithTimeout(ctx, tracingSpanWait)
	err := openJobSpans.wait(waitCtx)
	cancelWait()
	if err != nil {
		log.Debugln("Tracing: gave up waiting for transfer spans to end:", err)
	}
	if err := tracing.Flush(ctx); err != nil {
		log.Debugln("Tracing: failed to flush pending spans:", err)
	}
}

// offersTracingEndpoint reports whether this process takes its export
// endpoint from the federations its client discovers.  Only a client process
// does: a server is given its own federation's endpoint by its launcher, and
// the embedded client must not let some other federation choose where the
// server's spans go.  It is false when tracing is disabled.
func offersTracingEndpoint() bool {
	return tracing.DefaultService() == tracing.ServiceClient
}

// offerTracingEndpoint passes a federation's advertised collector endpoint to
// the tracing package once discovery has succeeded.
func offerTracingEndpoint(pUrl *pelican_url.PelicanURL) {
	if pUrl == nil || !offersTracingEndpoint() {
		return
	}
	tracing.OfferEndpoint(pUrl.FedInfo.TracingEndpoint)
}

// openSpanCounter counts the job spans started and not yet ended, so that
// FlushTracing can wait for spans that end in the background.  Starting and
// ending a span costs a locked increment or decrement; only a waiter
// allocates.
type openSpanCounter struct {
	mu      sync.Mutex
	open    int
	waiters []chan struct{}
}

// openJobSpans counts the process's open client.transfer spans.
var openJobSpans openSpanCounter

func (c *openSpanCounter) add() {
	c.mu.Lock()
	c.open++
	c.mu.Unlock()
}

func (c *openSpanCounter) done() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open--
	if c.open == 0 {
		for _, w := range c.waiters {
			close(w)
		}
		c.waiters = nil
	}
}

// wait returns once no span is open, or with ctx's error.
func (c *openSpanCounter) wait(ctx context.Context) error {
	c.mu.Lock()
	if c.open == 0 {
		c.mu.Unlock()
		return nil
	}
	w := make(chan struct{})
	c.waiters = append(c.waiters, w)
	c.mu.Unlock()
	select {
	case <-w:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// objectPathAttr is pelican.object.path for a URL path.  The path is cleaned,
// as the director, cache and origin clean it, so that every service records
// the same string for one object.
func objectPathAttr(urlPath string) attribute.KeyValue {
	return tracing.ObjectPath(path.Clean(urlPath))
}

// tracedOp is a span together with the context that holds it.  nil means the
// operation is not traced.
type tracedOp struct {
	ctx  context.Context
	span trace.Span
}

// startOp starts a span named name under the span in parent.  It returns nil
// when the span would not be recorded: always when tracing is disabled, and
// when parent holds no span (no trace is started here).
func startOp(parent context.Context, name string, attrs ...attribute.KeyValue) *tracedOp {
	if parent == nil || !tracing.Enabled() {
		return nil
	}
	ctx, span := tracing.StartChild(parent, name, trace.WithAttributes(attrs...))
	if !span.IsRecording() {
		span.End()
		return nil
	}
	return &tracedOp{ctx: ctx, span: span}
}

// child starts a span under o.
func (o *tracedOp) child(name string, attrs ...attribute.KeyValue) *tracedOp {
	if o == nil {
		return nil
	}
	return startOp(o.ctx, name, attrs...)
}

// carry returns base with o's span attached, leaving base's cancellation and
// values as they are.  It returns base itself when o is nil.
func (o *tracedOp) carry(base context.Context) context.Context {
	if o == nil {
		return base
	}
	return tracing.CarrySpan(base, o.ctx)
}

// set adds attributes to o's span.
func (o *tracedOp) set(attrs ...attribute.KeyValue) {
	if o == nil {
		return
	}
	o.span.SetAttributes(attrs...)
}

// end records err (scrubbed) on o's span, if non-nil, and ends it.
func (o *tracedOp) end(err error) {
	if o == nil {
		return
	}
	tracing.RecordError(o.span, err)
	o.span.End()
}

// addLogFields adds trace_id and span_id for o's span to fields.
func (o *tracedOp) addLogFields(fields log.Fields) {
	if o == nil {
		return
	}
	for k, v := range tracing.LogFields(o.ctx) {
		fields[k] = v
	}
}

// jobSpan is the client.transfer span of one download job.  It ends exactly
// once, whichever comes first of: job creation failing, the engine holding
// every result of the job (see jobResultArrived), and the job's context being
// cancelled.
type jobSpan struct {
	op      *tracedOp
	objects atomic.Int64
	failed  atomic.Int64

	// held counts the job's results that runMux has received from the
	// workers and not yet delivered to the client.  Only runMux touches it.
	held int64

	mu    sync.Mutex
	ended bool
	// stopWatch deregisters the cancellation watch set by endOnCancel.
	stopWatch func() bool
}

// startJobSpan starts the client.transfer span for a download of remoteUrl
// and returns the context holding it.  A client process starts a trace for
// it if ctx holds none; any other process traces the job only under the span
// already in ctx.  When the trace is sampled out the context still holds
// the (non-recording) span, so that the trace ID reaches the servers and they
// make the same sampling decision, but no *jobSpan is returned and no child
// span is created.  When the job is not traced ctx is returned unchanged.
func startJobSpan(ctx context.Context, remoteUrl *url.URL) (context.Context, *jobSpan) {
	svc := tracing.DefaultService()
	if svc == "" {
		return ctx, nil
	}
	start := tracing.StartChild
	if svc == tracing.ServiceClient {
		start = tracing.Start
	}
	ctx, span := start(ctx, spanTransfer)
	if !span.IsRecording() {
		span.End()
		return ctx, nil
	}
	span.SetAttributes(objectPathAttr(remoteUrl.Path))
	openJobSpans.add()
	return ctx, &jobSpan{op: &tracedOp{ctx: ctx, span: span}}
}

// child starts a span under the job span, from ctx (which must descend from
// the context startJobSpan returned).
func (js *jobSpan) child(ctx context.Context, name string, attrs ...attribute.KeyValue) *tracedOp {
	if js == nil {
		return nil
	}
	return startOp(ctx, name, attrs...)
}

// queryDirector starts a client.query_director span for a lookup of pUrl,
// from ctx (as for child).
func (js *jobSpan) queryDirector(ctx context.Context, pUrl *pelican_url.PelicanURL, withToken bool) *tracedOp {
	if js == nil {
		return nil
	}
	op := startOp(ctx, spanQueryDirector, attrDirectorWithToken.Bool(withToken))
	if op != nil {
		if u, err := url.Parse(pUrl.FedInfo.DirectorEndpoint); err == nil && u.Host != "" {
			op.set(attrDirectorEndpoint.String(u.Host))
		}
	}
	return op
}

// set adds attributes to the job span.
func (js *jobSpan) set(attrs ...attribute.KeyValue) {
	if js == nil {
		return
	}
	js.op.set(attrs...)
}

// describe records what NewTransferJob learned about the job once it has
// built it.
func (js *jobSpan) describe(tj *TransferJob) {
	if js == nil {
		return
	}
	js.set(attrTransferRecursive.Bool(tj.recursive))
	if tj.project != "" {
		js.set(attrClientProject.String(tj.project))
	}
}

// discovered records the outcome of federation discovery on op and, on
// success, the federation on the job span.
func (js *jobSpan) discovered(op *tracedOp, pUrl *pelican_url.PelicanURL, err error) {
	if js == nil {
		return
	}
	if err == nil && pUrl != nil && pUrl.FedInfo.DiscoveryEndpoint != "" {
		fed := tracing.Federation(pUrl.FedInfo.DiscoveryEndpoint)
		op.set(fed)
		js.set(fed)
	}
	op.end(err)
}

// setJobID records the X-Pelican-JobId the job's requests will carry.
func (js *jobSpan) setJobID(ctx context.Context) {
	if js == nil {
		return
	}
	if id, ok := getJobId(ctx); ok {
		js.set(tracing.JobID(id))
	}
}

// setNamespace records the namespace the director placed the object in.
func (js *jobSpan) setNamespace(namespace string) {
	if js == nil || namespace == "" {
		return
	}
	js.set(tracing.Namespace(namespace))
}

// endOnError ends the job span if job creation failed.
func (js *jobSpan) endOnError(err error) {
	if js == nil || err == nil {
		return
	}
	js.end(err)
}

// endOnCancel ends the job span, with the cancellation as its error, when
// ctx (the job's context) is cancelled before the job finished.  A job whose
// results never all reach the engine -- the caller stopped reading after a
// failure and cancelled the client, or cancelled the engine -- would
// otherwise never end its span.  Ending the span first deregisters the
// watch, so a finished job leaves nothing behind in a long-lived process.
func (js *jobSpan) endOnCancel(ctx context.Context) {
	if js == nil {
		return
	}
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.ended {
		return
	}
	js.stopWatch = context.AfterFunc(ctx, func() {
		js.end(context.Cause(ctx))
	})
}

// objectDone counts one finished object.
func (js *jobSpan) objectDone(failed bool) {
	js.objects.Add(1)
	if failed {
		js.failed.Add(1)
	}
}

// end ends the job span, at most once.  err is the job's own failure, if any;
// failed objects mark the span failed too.
func (js *jobSpan) end(err error) {
	if js == nil {
		return
	}
	js.mu.Lock()
	if js.ended {
		js.mu.Unlock()
		return
	}
	js.ended = true
	stop := js.stopWatch
	js.stopWatch = nil
	js.mu.Unlock()
	if stop != nil {
		stop()
	}

	objects := js.objects.Load()
	js.op.set(attrTransferObjects.Int64(objects))
	if err != nil {
		tracing.RecordError(js.op.span, err)
	} else if failed := js.failed.Load(); failed > 0 {
		js.op.span.SetStatus(codes.Error, fmt.Sprintf("%d of %d objects failed", failed, objects))
	}
	js.op.span.End()
	openJobSpans.done()
}

// jobResultArrived is called by runMux, on its goroutine, for every result a
// worker hands back for job: downloads, and the failures synthesized for
// transfers that never ran.  It counts the object and ends the job span once
// the engine holds every result of the job, which is before the client can
// receive the last of them.
func jobResultArrived(job *TransferJob, failed bool) {
	if job == nil || job.span == nil {
		return
	}
	job.span.objectDone(failed)
	job.span.held++
	job.span.endIfComplete(job)
}

// jobResultDelivered is called by runMux, on its goroutine, when it has
// delivered one of job's results to the client.
func jobResultDelivered(job *TransferJob) {
	if job == nil || job.span == nil {
		return
	}
	job.span.held--
}

// jobLookupFinished is called by runMux, on its goroutine, once job's lookup
// has handed every transfer to the workers.
func jobLookupFinished(job *TransferJob) {
	if job == nil || job.span == nil {
		return
	}
	job.span.endIfComplete(job)
}

// endIfComplete ends the job span if the job's lookup is done and every
// transfer it submitted has reported back to runMux.  activeXfer counts the
// transfers not yet delivered and held those received but not delivered, so
// the two are equal exactly when nothing is still running.  Once the lookup
// is done only runMux changes either, so the comparison is stable here.
func (js *jobSpan) endIfComplete(job *TransferJob) {
	if job.lookupDone.Load() && job.activeXfer.Load() == js.held {
		js.end(job.lookupErr)
	}
}

// startStatSpan starts the client.stat span for a stat of destination.
//
// The span is created only under an existing span: the cache and library
// callers stat inside a trace of their own, whereas a command's PlanDownload
// stats before its job (and so its trace) exists, and a lone stat span would
// be a trace of its own.  A stat of an upload destination is not traced.
func startStatSpan(ctx context.Context, destination string, options []TransferOption) *tracedOp {
	if !tracing.Enabled() {
		return nil
	}
	for _, option := range options {
		if option.Ident() == (identTransferOptionStatUploadDestination{}) && option.Value().(bool) {
			return nil
		}
	}
	op := startOp(ctx, spanStat)
	if op != nil {
		if u, err := url.Parse(destination); err == nil {
			op.set(objectPathAttr(u.Path))
		}
	}
	return op
}

// startObjectSpan starts the client.download_object span for transfer.  It
// returns nil for anything but a download belonging to a traced job.
func startObjectSpan(transfer *transferFile) *tracedOp {
	if transfer.xferType != transferTypeDownload || transfer.job == nil || transfer.job.span == nil || transfer.ctx == nil {
		return nil
	}
	var attrs []attribute.KeyValue
	if transfer.remoteURL != nil {
		attrs = append(attrs, objectPathAttr(transfer.remoteURL.Path))
	}
	return startOp(transfer.ctx, spanDownloadObject, attrs...)
}

// endObject ends the client.download_object span with what downloadObject
// returned.  The object is counted on the job span by runMux, which sees
// every result, including those that never pass through downloadObject.
func (o *tracedOp) endObject(results TransferResults, err error) {
	if o == nil {
		return
	}
	o.set(tracing.TransferBytes(results.TransferredBytes), attrTransferAttempts.Int(len(results.Attempts)))
	if err == nil {
		err = results.Error
	}
	o.end(err)
}

// sortAttempts is sortAttempts under a client.sort_attempts span.  ctx is the
// context the probes would otherwise run under; it keeps its cancellation and
// values and gains the span.
func (o *tracedOp) sortAttempts(ctx context.Context, path string, attempts []transferAttemptDetails, token *tokenGenerator, wantCollectionInfo bool) (int64, collectionAnswer, []transferAttemptDetails) {
	if o == nil {
		return sortAttempts(ctx, path, attempts, token, wantCollectionInfo)
	}
	op := o.child(spanSortAttempts, attrAttemptCandidates.Int(len(attempts)))
	size, collection, results := sortAttempts(op.carry(ctx), path, attempts, token, wantCollectionInfo)
	op.end(nil)
	return size, collection, results
}

// startAttempt starts a client.attempt span under the object span.
func (o *tracedOp) startAttempt(number int, endpoint string) *tracedOp {
	if o == nil {
		return nil
	}
	return o.child(spanAttempt, attrAttemptNumber.Int(number), attrAttemptEndpoint.String(endpoint))
}

// endAttempt ends a client.attempt span with the attempt's outcome.  err is
// what downloadHTTP returned; the recorded error is attempt.Error when set,
// which is the form the transfer results report.
func (o *tracedOp) endAttempt(attempt TransferResult, err error) {
	if o == nil {
		return
	}
	o.set(attrAttemptBytes.Int64(attempt.TransferFileBytes))
	if attempt.CacheAge >= 0 {
		o.set(attrAttemptCacheAgeS.Int64(int64(attempt.CacheAge / time.Second)))
	}
	if attempt.ServerVersion != "" {
		o.set(attrAttemptServerVersion.String(attempt.ServerVersion))
	}
	if attempt.Error != nil {
		err = attempt.Error
	}
	if err != nil {
		o.set(attrAttemptRetryable.Bool(IsRetryable(err)))
	}
	o.end(err)
}

// recordTimeToFirstByte sets the attempt's time to first byte, measured from
// start, on the span in ctx.  downloadHTTP runs only inside a download
// attempt, under that attempt's context, and a span in it is recording only
// when the attempt is traced; so a recording span there is the
// client.attempt span.  It does nothing when no byte arrived.
func recordTimeToFirstByte(ctx context.Context, start, firstByte time.Time) {
	if !tracing.Enabled() || firstByte.IsZero() {
		return
	}
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(attrAttemptTimeToFirstByte.Float64(float64(firstByte.Sub(start)) / float64(time.Millisecond)))
}
