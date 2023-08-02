package main

import (
	"crypto/elliptic"
	"os"
	"os/signal"
	"syscall"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func generateTLSCertIfNeeded() error {

	// As necessary, generate a private key and corresponding cert
	if err := config.GeneratePrivateKey(viper.GetString("TLSKey"), elliptic.P256()); err != nil {
		return err
	}
	if err := config.GenerateCert(); err != nil {
		return err
	}

	return nil
}

func serveDirector( /*cmd*/ *cobra.Command /*args*/, []string) error {
	log.Info("Initializing Director GeoIP database...")
	director.InitializeDB()

	if config.GetPreferredPrefix() == "OSDF" {
		log.Info("Generating/advertising server ads from OSG topology service...")

		// Get the ads from topology, populate the cache, and keep the cache
		// updated with fresh info
		if err := director.AdvertiseOSDF(); err != nil {
			panic(err)
		}
	}
	go director.PeriodicCacheReload()

	err := generateTLSCertIfNeeded()
	if err != nil {
		return err
	}

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
