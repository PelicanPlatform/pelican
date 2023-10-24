// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This package started as a fork of the `prometheus` CLI executable and was
// heavily adapted to make it embedded into the pelican web UI.
package web_ui

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/units"
	"github.com/gin-gonic/gin"
	kit_log "github.com/go-kit/kit/log/logrus"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/regexp"
	"github.com/mwitkow/go-conntrack"
	"github.com/oklog/run"
	pelican_config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/version"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"

	common_config "github.com/prometheus/common/config"
	"github.com/prometheus/common/route"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/metadata"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/scrape"
	"github.com/prometheus/prometheus/storage"

	//"github.com/prometheus/prometheus/storage/remote"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/agent"
	"github.com/prometheus/prometheus/tsdb/wlog"
	"github.com/prometheus/prometheus/web"
	api_v1 "github.com/prometheus/prometheus/web/api/v1"
)

var (
	appName = "prometheus"

	defaultRetentionString   = "15d"
	defaultRetentionDuration model.Duration

	globalConfig    config.Config
	globalConfigMtx sync.RWMutex
)

func init() {
	prometheus.MustRegister(version.NewCollector(strings.ReplaceAll(appName, "-", "_")))

	var err error
	defaultRetentionDuration, err = model.ParseDuration(defaultRetentionString)
	if err != nil {
		panic(err)
	}
}

type flagConfig struct {
	serverStoragePath   string
	forGracePeriod      model.Duration
	outageTolerance     model.Duration
	resendDelay         model.Duration
	scrape              scrape.Options
	tsdb                tsdbOptions
	lookbackDelta       model.Duration
	webTimeout          model.Duration
	queryTimeout        model.Duration
	queryConcurrency    int
	queryMaxSamples     int
	RemoteFlushDeadline model.Duration

	enableExpandExternalLabels bool
	enablePerStepStats         bool
}

type ReadyHandler struct {
	ready atomic.Uint32
}

func (h *ReadyHandler) SetReady(v bool) {
	if v {
		h.ready.Store(1)
		return
	}

	h.ready.Store(0)
}

func (h *ReadyHandler) isReady() bool {
	return h.ready.Load() > 0
}

func (h *ReadyHandler) testReady(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.isReady() {
			f(w, r)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "Service Unavailable")
		}
	}
}

func runtimeInfo() (api_v1.RuntimeInfo, error) {
	return api_v1.RuntimeInfo{}, nil
}

func checkPromToken(av1 *route.Router) gin.HandlerFunc {
	/* A function which wraps around the av1 router to force a jwk token check using
	 * the origin's private key. It will check the request's URL and Header for a token
	 * and if found it will then attempt to validate the token. If valid, it will continue
	 * the routing as normal, otherwise it will return an error"
	 */
	return func(c *gin.Context) {
		req := c.Request

		var strToken string
		var err error
		if authzQuery := req.URL.Query()["authz"]; len(authzQuery) > 0 {
			strToken = authzQuery[0]
		} else if authzHeader := req.Header["Authorization"]; len(authzHeader) > 0 {
			strToken = strings.TrimPrefix(authzHeader[0], "Bearer ")
		}

		FederationCheck(c, strToken, "prometheus.read")
		OriginCheck(c, strToken, "prometheus.read")

		strToken, err = c.Cookie("login")
		if err == nil {
			OriginCheck(c, strToken, "prometheus.read")
		}

		_, exists := c.Get("User")
		if exists {
			av1.ServeHTTP(c.Writer, c.Request)
		} else {
			c.JSON(http.StatusForbidden, gin.H{"error": "Correct authorization required to access metrics"})
		}
	}
}

func ConfigureEmbeddedPrometheus(engine *gin.Engine, isDirector bool) error {
	cfg := flagConfig{}
	ListenAddress := fmt.Sprintf("0.0.0.0:%v", param.Server_Port.GetInt())
	cfg.webTimeout = model.Duration(5 * time.Minute)
	cfg.serverStoragePath = param.Monitoring_DataLocation.GetString()
	cfg.tsdb.MinBlockDuration = model.Duration(2 * time.Hour)
	cfg.tsdb.NoLockfile = false
	cfg.tsdb.WALCompression = true
	cfg.tsdb.HeadChunksWriteQueueSize = 0
	cfg.tsdb.SamplesPerChunk = 120
	cfg.RemoteFlushDeadline = model.Duration(1 * time.Minute)
	cfg.outageTolerance = model.Duration(1 * time.Hour)
	cfg.forGracePeriod = model.Duration(10 * time.Minute)
	cfg.resendDelay = model.Duration(1 * time.Minute)
	cfg.lookbackDelta = model.Duration(5 * time.Minute)
	cfg.queryTimeout = model.Duration(2 * time.Minute)
	cfg.queryConcurrency = 20
	cfg.queryMaxSamples = 50000000
	cfg.scrape.DiscoveryReloadInterval = model.Duration(5 * time.Second)

	RemoteReadSampleLimit := int(5e7)
	RemoteReadConcurrencyLimit := 10
	RemoteReadBytesInFrame := 1048576

	scrape.AlignScrapeTimestamps = true
	scrape.ScrapeTimestampTolerance = 2 * time.Millisecond

	logger := kit_log.NewLogger(logrus.WithFields(logrus.Fields{"component": "prometheus"}))

	localStoragePath := cfg.serverStoragePath

	external_url, err := url.Parse("https://" + pelican_config.ComputeExternalAddress())
	if err != nil {
		return fmt.Errorf("parse external URL https://%v: %w", pelican_config.ComputeExternalAddress(), err)
	}

	CORSOrigin, err := compileCORSRegexString(".*")
	if err != nil {
		panic(err)
	}

	// Throw error for invalid config before starting other components.
	promCfg := config.Config{
		GlobalConfig:  config.DefaultGlobalConfig,
		ScrapeConfigs: make([]*config.ScrapeConfig, 1),
	}
	scrapeConfig := config.DefaultScrapeConfig
	scrapeConfig.JobName = "prometheus"
	scrapeConfig.Scheme = "https"
	scrapeConfig.ServiceDiscoveryConfigs = make([]discovery.Config, 1)
	scrapeConfig.ServiceDiscoveryConfigs[0] = discovery.StaticConfig{
		&targetgroup.Group{
			Targets: []model.LabelSet{{
				model.AddressLabel: model.LabelValue(pelican_config.ComputeExternalAddress()),
			}},
		},
	}
	scrapeConfig.HTTPClientConfig = common_config.DefaultHTTPClientConfig
	scrapeConfig.HTTPClientConfig.TLSConfig.InsecureSkipVerify = true
	promCfg.ScrapeConfigs[0] = &scrapeConfig
	promCfg.GlobalConfig.ScrapeInterval = model.Duration(15 * time.Second)

	if promCfg.StorageConfig.TSDBConfig != nil {
		cfg.tsdb.OutOfOrderTimeWindow = promCfg.StorageConfig.TSDBConfig.OutOfOrderTimeWindow
	}

	cfg.tsdb.RetentionDuration = defaultRetentionDuration

	// Max block size settings.
	if cfg.tsdb.MaxBlockDuration == 0 {
		maxBlockDuration, err := model.ParseDuration("31d")
		if err != nil {
			panic(err)
		}
		// When the time retention is set and not too big use to define the max block duration.
		if cfg.tsdb.RetentionDuration != 0 && cfg.tsdb.RetentionDuration/10 < maxBlockDuration {
			maxBlockDuration = cfg.tsdb.RetentionDuration / 10
		}

		cfg.tsdb.MaxBlockDuration = maxBlockDuration
	}

	noStepSubqueryInterval := &safePromQLNoStepSubqueryInterval{}
	noStepSubqueryInterval.Set(config.DefaultGlobalConfig.EvaluationInterval)

	var (
		localStorage = &readyStorage{stats: tsdb.NewDBStats()}
		scraper      = &readyScrapeManager{}
		//remoteStorage = remote.NewStorage(log.With(logger, "component", "remote"), prometheus.DefaultRegisterer, localStorage.StartTime, localStoragePath, time.Duration(cfg.RemoteFlushDeadline), scraper)
		//fanoutStorage = storage.NewFanout(logger, localStorage, remoteStorage)
		fanoutStorage = storage.NewFanout(logger, localStorage)
	)

	var (
		//ctxWeb, cancelWeb = context.WithCancel(context.Background())
		//ctxRule           = context.Background()

		ctxScrape, cancelScrape = context.WithCancel(context.Background())
		discoveryManagerScrape  discoveryManager
	)

	discovery.RegisterMetrics()
	discoveryManagerScrape = discovery.NewManager(ctxScrape, log.With(logger, "component", "discovery manager scrape"), discovery.Name("scrape"))

	var (
		scrapeManager = scrape.NewManager(&cfg.scrape, log.With(logger, "component", "scrape manager"), fanoutStorage)

		queryEngine *promql.Engine
	)

	{
		opts := promql.EngineOpts{
			Logger:                   log.With(logger, "component", "query engine"),
			Reg:                      prometheus.DefaultRegisterer,
			MaxSamples:               cfg.queryMaxSamples,
			Timeout:                  time.Duration(cfg.queryTimeout),
			ActiveQueryTracker:       promql.NewActiveQueryTracker(localStoragePath, cfg.queryConcurrency, log.With(logger, "component", "activeQueryTracker")),
			LookbackDelta:            time.Duration(cfg.lookbackDelta),
			NoStepSubqueryIntervalFn: noStepSubqueryInterval.Get,
			// EnableAtModifier and EnableNegativeOffset have to be
			// always on for regular PromQL as of Prometheus v2.33.
			EnableAtModifier:     true,
			EnableNegativeOffset: true,
			EnablePerStepStats:   cfg.enablePerStepStats,
		}

		queryEngine = promql.NewEngine(opts)

	}
	scraper.Set(scrapeManager)

	TSDBDir := localStoragePath

	Version := &web.PrometheusVersion{
		Version:   version.Version,
		Revision:  version.Revision,
		Branch:    version.Branch,
		BuildUser: version.BuildUser,
		BuildDate: version.BuildDate,
		GoVersion: version.GoVersion,
	}

	Flags := map[string]string{}

	// Depends on cfg.web.ScrapeManager so needs to be after cfg.web.ScrapeManager = scrapeManager.
	// webHandler := web.New(log.With(logger, "component", "web"), &cfg.web)

	// Monitor outgoing connections on default transport with conntrack.
	http.DefaultTransport.(*http.Transport).DialContext = conntrack.NewDialContextFunc(
		conntrack.DialWithTracing(),
	)

	factorySPr := func(_ context.Context) api_v1.ScrapePoolsRetriever { return scrapeManager }
	factoryTr := func(_ context.Context) api_v1.TargetRetriever { return scrapeManager }
	factoryAr := func(_ context.Context) api_v1.AlertmanagerRetriever { return nil }
	FactoryRr := func(_ context.Context) api_v1.RulesRetriever { return nil }

	readyHandler := ReadyHandler{}
	readyHandler.SetReady(false)

	var app storage.Appendable
	apiV1 := api_v1.NewAPI(
		queryEngine,
		fanoutStorage,
		app,
		localStorage,
		factorySPr,
		factoryTr,
		factoryAr,
		func() config.Config {
			globalConfigMtx.RLock()
			defer globalConfigMtx.RUnlock()
			return globalConfig
		},
		Flags,
		api_v1.GlobalURLOptions{
			ListenAddress: ListenAddress,
			Host:          external_url.Host,
			Scheme:        external_url.Scheme,
		},
		readyHandler.testReady,
		localStorage,
		TSDBDir,
		false,
		logger,
		FactoryRr,
		RemoteReadSampleLimit,
		RemoteReadConcurrencyLimit,
		RemoteReadBytesInFrame,
		false,
		CORSOrigin,
		runtimeInfo,
		Version,
		prometheus.DefaultGatherer,
		prometheus.DefaultRegisterer,
		nil,
	)
	av1 := route.New().WithPrefix("/api/v1.0/prometheus")
	//WithInstrumentation(h.metrics.instrumentHandlerWithPrefix("/api/v1")).
	//WithInstrumentation(setPathWithPrefix("/api/v1"))
	apiV1.Register(av1)

	engine.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))

	reloaders := []reloader{
		{
			name:     "db_storage",
			reloader: localStorage.ApplyConfig,
		}, /* {
			name:     "web_handler",
			reloader: webHandler.ApplyConfig,
		},*/{
			name: "query_engine",
			reloader: func(cfg *config.Config) error {
				queryEngine.SetQueryLogger(nil)
				return nil
			},
		}, {
			name:     "scrape",
			reloader: scrapeManager.ApplyConfig,
		}, {
			name: "scrape_sd",
			reloader: func(cfg *config.Config) error {
				c := make(map[string]discovery.Configs)
				scfgs, err := cfg.GetScrapeConfigs()
				if err != nil {
					return err
				}
				for _, v := range scfgs {
					c[v.JobName] = v.ServiceDiscoveryConfigs
				}
				return discoveryManagerScrape.ApplyConfig(c)
			},
		},
	}

	// Start all components while we wait for TSDB to open but only load
	// initial config and mark ourselves as ready after it completed.
	dbOpen := make(chan struct{})

	// sync.Once is used to make sure we can close the channel at different execution stages(SIGTERM or when the config is loaded).
	type closeOnce struct {
		C     chan struct{}
		once  sync.Once
		Close func()
	}
	// Wait until the server is ready to handle reloading.
	reloadReady := &closeOnce{
		C: make(chan struct{}),
	}
	reloadReady.Close = func() {
		reloadReady.once.Do(func() {
			close(reloadReady.C)
		})
	}
	var g run.Group
	{
		// Termination handler.
		term := make(chan os.Signal, 1)
		signal.Notify(term, os.Interrupt, syscall.SIGTERM)
		cancel := make(chan struct{})
		g.Add(
			func() error {
				// Don't forget to release the reloadReady channel so that waiting blocks can exit normally.
				select {
				case <-term:
					err := level.Warn(logger).Log("msg", "Received SIGTERM, exiting gracefully...")
					_ = err
					reloadReady.Close()
				//case <-webHandler.Quit():
				//	level.Warn(logger).Log("msg", "Received termination request via web service, exiting gracefully...")
				case <-cancel:
					reloadReady.Close()
				}
				return nil
			},
			func(err error) {
				close(cancel)
				//webHandler.SetReady(false)
				readyHandler.SetReady(false)
			},
		)
	}
	{
		// Scrape discovery manager.
		g.Add(
			func() error {
				err := discoveryManagerScrape.Run()
				err2 := level.Info(logger).Log("msg", "Scrape discovery manager stopped")
				_ = err2
				return err
			},
			func(err error) {
				err2 := level.Info(logger).Log("msg", "Stopping scrape discovery manager...")
				_ = err2
				cancelScrape()
			},
		)
	}
	{
		// Scrape manager.
		g.Add(
			func() error {
				// When the scrape manager receives a new targets list
				// it needs to read a valid config for each job.
				// It depends on the config being in sync with the discovery manager so
				// we wait until the config is fully loaded.
				<-reloadReady.C

				err := scrapeManager.Run(discoveryManagerScrape.SyncCh())
				err2 := level.Info(logger).Log("msg", "Scrape manager stopped")
				_ = err2
				return err
			},
			func(err error) {
				// Scrape manager needs to be stopped before closing the local TSDB
				// so that it doesn't try to write samples to a closed storage.
				// We should also wait for rule manager to be fully stopped to ensure
				// we don't trigger any false positive alerts for rules using absent().
				err2 := level.Info(logger).Log("msg", "Stopping scrape manager...")
				_ = err2
				scrapeManager.Stop()
			},
		)
	}
	{
		cancel := make(chan struct{})
		g.Add(
			func() error {
				select {
				case <-dbOpen:
				case <-cancel:
					reloadReady.Close()
					return nil
				}

				if err := reloadConfig(&promCfg, cfg.enableExpandExternalLabels, cfg.tsdb.EnableExemplarStorage, logger, noStepSubqueryInterval, reloaders...); err != nil {
					return fmt.Errorf("error loading config: %w", err)
				}
				reloadReady.Close()

				readyHandler.SetReady(true)
				err2 := level.Info(logger).Log("msg", "Server is ready to receive web requests.")
				_ = err2
				<-cancel
				return nil
			},
			func(err error) {
				close(cancel)
			},
		)

	}
	{
		// TSDB.
		opts := cfg.tsdb.ToTSDBOptions()
		cancel := make(chan struct{})
		g.Add(
			func() error {
				err = level.Info(logger).Log("msg", "Starting TSDB ...")
				_ = err
				if cfg.tsdb.WALSegmentSize != 0 {
					if cfg.tsdb.WALSegmentSize < 10*1024*1024 || cfg.tsdb.WALSegmentSize > 256*1024*1024 {
						return errors.New("flag 'storage.tsdb.wal-segment-size' must be set between 10MB and 256MB")
					}
				}
				if cfg.tsdb.MaxBlockChunkSegmentSize != 0 {
					if cfg.tsdb.MaxBlockChunkSegmentSize < 1024*1024 {
						return errors.New("flag 'storage.tsdb.max-block-chunk-segment-size' must be set over 1MB")
					}
				}

				db, err := openDBWithMetrics(localStoragePath, logger, prometheus.DefaultRegisterer, &opts, localStorage.getStats())
				if err != nil {
					return fmt.Errorf("opening storage failed: %w", err)
				}

				err = level.Info(logger).Log("msg", "TSDB started")
				_ = err
				err = level.Debug(logger).Log("msg", "TSDB options",
					"MinBlockDuration", cfg.tsdb.MinBlockDuration,
					"MaxBlockDuration", cfg.tsdb.MaxBlockDuration,
					"MaxBytes", cfg.tsdb.MaxBytes,
					"NoLockfile", cfg.tsdb.NoLockfile,
					"RetentionDuration", cfg.tsdb.RetentionDuration,
					"WALSegmentSize", cfg.tsdb.WALSegmentSize,
					"WALCompression", cfg.tsdb.WALCompression,
				)
				_ = err

				startTimeMargin := int64(2 * time.Duration(cfg.tsdb.MinBlockDuration).Seconds() * 1000)
				localStorage.Set(db, startTimeMargin)
				//db.SetWriteNotified(remoteStorage)
				close(dbOpen)
				<-cancel
				return nil
			},
			func(err error) {
				if err := fanoutStorage.Close(); err != nil {
					err = level.Error(logger).Log("msg", "Error stopping storage", "err", err)
					_ = err
				}
				close(cancel)
			},
		)
	}
	go func() {
		if err := g.Run(); err != nil {
			err = level.Error(logger).Log("err", err)
			_ = err
		}
	}()

	return nil
}

func openDBWithMetrics(dir string, logger log.Logger, reg prometheus.Registerer, opts *tsdb.Options, stats *tsdb.DBStats) (*tsdb.DB, error) {
	db, err := tsdb.Open(
		dir,
		log.With(logger, "component", "tsdb"),
		reg,
		opts,
		stats,
	)
	if err != nil {
		return nil, err
	}

	reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "prometheus_tsdb_lowest_timestamp_seconds",
			Help: "Lowest timestamp value stored in the database.",
		}, func() float64 {
			bb := db.Blocks()
			if len(bb) == 0 {
				return float64(db.Head().MinTime() / 1000)
			}
			return float64(db.Blocks()[0].Meta().MinTime / 1000)
		}), prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "prometheus_tsdb_head_min_time_seconds",
			Help: "Minimum time bound of the head block.",
		}, func() float64 { return float64(db.Head().MinTime() / 1000) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "prometheus_tsdb_head_max_time_seconds",
			Help: "Maximum timestamp of the head block.",
		}, func() float64 { return float64(db.Head().MaxTime() / 1000) }),
	)

	return db, nil
}

type safePromQLNoStepSubqueryInterval struct {
	value atomic.Int64
}

func durationToInt64Millis(d time.Duration) int64 {
	return int64(d / time.Millisecond)
}

func (i *safePromQLNoStepSubqueryInterval) Set(ev model.Duration) {
	i.value.Store(durationToInt64Millis(time.Duration(ev)))
}

func (i *safePromQLNoStepSubqueryInterval) Get(int64) int64 {
	return i.value.Load()
}

type reloader struct {
	name     string
	reloader func(*config.Config) error
}

func reloadConfig(conf *config.Config, expandExternalLabels, enableExemplarStorage bool, logger log.Logger, noStepSuqueryInterval *safePromQLNoStepSubqueryInterval, rls ...reloader) (err error) {
	start := time.Now()
	timings := []interface{}{}

	{
		globalConfigMtx.Lock()
		defer globalConfigMtx.Unlock()
		globalConfig = *conf
	}

	failed := false
	for _, rl := range rls {
		rstart := time.Now()
		if err := rl.reloader(conf); err != nil {
			err = level.Error(logger).Log("msg", "Failed to apply configuration", "err", err)
			_ = err
			failed = true
		}
		timings = append(timings, rl.name, time.Since(rstart))
	}
	if failed {
		return fmt.Errorf("one or more errors occurred while applying the new configuration")
	}

	noStepSuqueryInterval.Set(conf.GlobalConfig.EvaluationInterval)
	l := []interface{}{"msg", "Completed loading of configuration", "totalDuration", time.Since(start)}
	err = level.Info(logger).Log(append(l, timings...)...)
	_ = err
	return nil
}

// compileCORSRegexString compiles given string and adds anchors
func compileCORSRegexString(s string) (*regexp.Regexp, error) {
	r, err := relabel.NewRegexp(s)
	if err != nil {
		return nil, err
	}
	return r.Regexp, nil
}

// readyStorage implements the Storage interface while allowing to set the actual
// storage at a later point in time.
type readyStorage struct {
	mtx             sync.RWMutex
	db              storage.Storage
	startTimeMargin int64
	stats           *tsdb.DBStats
}

func (s *readyStorage) ApplyConfig(conf *config.Config) error {
	db := s.get()
	if db, ok := db.(*tsdb.DB); ok {
		return db.ApplyConfig(conf)
	}
	return nil
}

// Set the storage.
func (s *readyStorage) Set(db storage.Storage, startTimeMargin int64) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.db = db
	s.startTimeMargin = startTimeMargin
}

func (s *readyStorage) get() storage.Storage {
	s.mtx.RLock()
	x := s.db
	s.mtx.RUnlock()
	return x
}

func (s *readyStorage) getStats() *tsdb.DBStats {
	s.mtx.RLock()
	x := s.stats
	s.mtx.RUnlock()
	return x
}

// StartTime implements the Storage interface.
func (s *readyStorage) StartTime() (int64, error) {
	if x := s.get(); x != nil {
		switch db := x.(type) {
		case *tsdb.DB:
			var startTime int64
			if len(db.Blocks()) > 0 {
				startTime = db.Blocks()[0].Meta().MinTime
			} else {
				startTime = time.Now().Unix() * 1000
			}
			// Add a safety margin as it may take a few minutes for everything to spin up.
			return startTime + s.startTimeMargin, nil
		case *agent.DB:
			return db.StartTime()
		default:
			panic(fmt.Sprintf("unknown storage type %T", db))
		}
	}

	return math.MaxInt64, tsdb.ErrNotReady
}

// Querier implements the Storage interface.
func (s *readyStorage) Querier(ctx context.Context, mint, maxt int64) (storage.Querier, error) {
	if x := s.get(); x != nil {
		return x.Querier(ctx, mint, maxt)
	}
	return nil, tsdb.ErrNotReady
}

// ChunkQuerier implements the Storage interface.
func (s *readyStorage) ChunkQuerier(ctx context.Context, mint, maxt int64) (storage.ChunkQuerier, error) {
	if x := s.get(); x != nil {
		return x.ChunkQuerier(ctx, mint, maxt)
	}
	return nil, tsdb.ErrNotReady
}

func (s *readyStorage) ExemplarQuerier(ctx context.Context) (storage.ExemplarQuerier, error) {
	if x := s.get(); x != nil {
		switch db := x.(type) {
		case *tsdb.DB:
			return db.ExemplarQuerier(ctx)
		case *agent.DB:
			return nil, agent.ErrUnsupported
		default:
			panic(fmt.Sprintf("unknown storage type %T", db))
		}
	}
	return nil, tsdb.ErrNotReady
}

// Appender implements the Storage interface.
func (s *readyStorage) Appender(ctx context.Context) storage.Appender {
	if x := s.get(); x != nil {
		return x.Appender(ctx)
	}
	return notReadyAppender{}
}

type notReadyAppender struct{}

func (n notReadyAppender) Append(ref storage.SeriesRef, l labels.Labels, t int64, v float64) (storage.SeriesRef, error) {
	return 0, tsdb.ErrNotReady
}

func (n notReadyAppender) AppendExemplar(ref storage.SeriesRef, l labels.Labels, e exemplar.Exemplar) (storage.SeriesRef, error) {
	return 0, tsdb.ErrNotReady
}

func (n notReadyAppender) AppendHistogram(ref storage.SeriesRef, l labels.Labels, t int64, h *histogram.Histogram, fh *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return 0, tsdb.ErrNotReady
}

func (n notReadyAppender) UpdateMetadata(ref storage.SeriesRef, l labels.Labels, m metadata.Metadata) (storage.SeriesRef, error) {
	return 0, tsdb.ErrNotReady
}

func (n notReadyAppender) Commit() error { return tsdb.ErrNotReady }

func (n notReadyAppender) Rollback() error { return tsdb.ErrNotReady }

// Close implements the Storage interface.
func (s *readyStorage) Close() error {
	if x := s.get(); x != nil {
		return x.Close()
	}
	return nil
}

// CleanTombstones implements the api_v1.TSDBAdminStats and api_v2.TSDBAdmin interfaces.
func (s *readyStorage) CleanTombstones() error {
	if x := s.get(); x != nil {
		switch db := x.(type) {
		case *tsdb.DB:
			return db.CleanTombstones()
		case *agent.DB:
			return agent.ErrUnsupported
		default:
			panic(fmt.Sprintf("unknown storage type %T", db))
		}
	}
	return tsdb.ErrNotReady
}

// Delete implements the api_v1.TSDBAdminStats and api_v2.TSDBAdmin interfaces.
func (s *readyStorage) Delete(mint, maxt int64, ms ...*labels.Matcher) error {
	if x := s.get(); x != nil {
		switch db := x.(type) {
		case *tsdb.DB:
			return db.Delete(mint, maxt, ms...)
		case *agent.DB:
			return agent.ErrUnsupported
		default:
			panic(fmt.Sprintf("unknown storage type %T", db))
		}
	}
	return tsdb.ErrNotReady
}

// Snapshot implements the api_v1.TSDBAdminStats and api_v2.TSDBAdmin interfaces.
func (s *readyStorage) Snapshot(dir string, withHead bool) error {
	if x := s.get(); x != nil {
		switch db := x.(type) {
		case *tsdb.DB:
			return db.Snapshot(dir, withHead)
		case *agent.DB:
			return agent.ErrUnsupported
		default:
			panic(fmt.Sprintf("unknown storage type %T", db))
		}
	}
	return tsdb.ErrNotReady
}

// Stats implements the api_v1.TSDBAdminStats interface.
func (s *readyStorage) Stats(statsByLabelName string, limit int) (*tsdb.Stats, error) {
	if x := s.get(); x != nil {
		switch db := x.(type) {
		case *tsdb.DB:
			return db.Head().Stats(statsByLabelName, limit), nil
		case *agent.DB:
			return nil, agent.ErrUnsupported
		default:
			panic(fmt.Sprintf("unknown storage type %T", db))
		}
	}
	return nil, tsdb.ErrNotReady
}

// WALReplayStatus implements the api_v1.TSDBStats interface.
func (s *readyStorage) WALReplayStatus() (tsdb.WALReplayStatus, error) {
	if x := s.getStats(); x != nil {
		return x.Head.WALReplayStatus.GetWALReplayStatus(), nil
	}
	return tsdb.WALReplayStatus{}, tsdb.ErrNotReady
}

// ErrNotReady is returned if the underlying scrape manager is not ready yet.
var ErrNotReady = errors.New("Scrape manager not ready")

// ReadyScrapeManager allows a scrape manager to be retrieved. Even if it's set at a later point in time.
type readyScrapeManager struct {
	mtx sync.RWMutex
	m   *scrape.Manager
}

// Set the scrape manager.
func (rm *readyScrapeManager) Set(m *scrape.Manager) {
	rm.mtx.Lock()
	defer rm.mtx.Unlock()

	rm.m = m
}

// Get the scrape manager. If is not ready, return an error.
func (rm *readyScrapeManager) Get() (*scrape.Manager, error) {
	rm.mtx.RLock()
	defer rm.mtx.RUnlock()

	if rm.m != nil {
		return rm.m, nil
	}

	return nil, ErrNotReady
}

// tsdbOptions is tsdb.Option version with defined units.
// This is required as tsdb.Option fields are unit agnostic (time).
type tsdbOptions struct {
	WALSegmentSize                 units.Base2Bytes
	MaxBlockChunkSegmentSize       units.Base2Bytes
	RetentionDuration              model.Duration
	MaxBytes                       units.Base2Bytes
	NoLockfile                     bool
	WALCompression                 bool
	WALCompressionType             string
	HeadChunksWriteQueueSize       int
	SamplesPerChunk                int
	StripeSize                     int
	MinBlockDuration               model.Duration
	MaxBlockDuration               model.Duration
	OutOfOrderTimeWindow           int64
	EnableExemplarStorage          bool
	MaxExemplars                   int64
	EnableMemorySnapshotOnShutdown bool
	EnableNativeHistograms         bool
}

func (opts tsdbOptions) ToTSDBOptions() tsdb.Options {
	return tsdb.Options{
		WALSegmentSize:                 int(opts.WALSegmentSize),
		MaxBlockChunkSegmentSize:       int64(opts.MaxBlockChunkSegmentSize),
		RetentionDuration:              int64(time.Duration(opts.RetentionDuration) / time.Millisecond),
		MaxBytes:                       int64(opts.MaxBytes),
		NoLockfile:                     opts.NoLockfile,
		AllowOverlappingCompaction:     true,
		WALCompression:                 wlog.ParseCompressionType(opts.WALCompression, opts.WALCompressionType),
		HeadChunksWriteQueueSize:       opts.HeadChunksWriteQueueSize,
		SamplesPerChunk:                opts.SamplesPerChunk,
		StripeSize:                     opts.StripeSize,
		MinBlockDuration:               int64(time.Duration(opts.MinBlockDuration) / time.Millisecond),
		MaxBlockDuration:               int64(time.Duration(opts.MaxBlockDuration) / time.Millisecond),
		EnableExemplarStorage:          opts.EnableExemplarStorage,
		MaxExemplars:                   opts.MaxExemplars,
		EnableMemorySnapshotOnShutdown: opts.EnableMemorySnapshotOnShutdown,
		EnableNativeHistograms:         opts.EnableNativeHistograms,
		OutOfOrderTimeWindow:           opts.OutOfOrderTimeWindow,
	}
}

// discoveryManager interfaces the discovery manager. This is used to keep using
// the manager that restarts SD's on reload for a few releases until we feel
// the new manager can be enabled for all users.
type discoveryManager interface {
	ApplyConfig(cfg map[string]discovery.Configs) error
	Run() error
	SyncCh() <-chan map[string][]*targetgroup.Group
}
