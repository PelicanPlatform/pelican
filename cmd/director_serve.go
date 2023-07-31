package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func serveDirector( /*cmd*/ *cobra.Command /*args*/, []string) error {
	log.Info("Initializing Director GeoIP database...")
	director.InitializeDB()

	log.Info("Generating/advertising server ads...")

	// Get the ads from topology, populate the cache, and keep the cache
	// updated with fresh info
	if err := director.AdvertiseOSDF(); err != nil {
		panic(err)
	}
	go director.PeriodicCacheReload()

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	// Use the shortcut middleware so that GET /foo/bar
	// acts the same as GET /api/v1.0/director/object/foo/bar
	engine.Use(director.ShortcutMiddleware())
	director.RegisterDirector(engine.Group("/"))

	log.Info("Starting web engine...")
	go web_ui.RunEngine(engine)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig

	return nil
}
