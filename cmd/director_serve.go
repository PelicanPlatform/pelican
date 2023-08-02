package main

import (
	"crypto/elliptic"
	"errors"
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

	// Configure the shortcut middleware to either redirect to a cache
	// or to an origin
	defaultEndpoint := viper.GetString("DirectorDefaultEndpoint")
	if !(defaultEndpoint == "cache" || defaultEndpoint == "origin" || defaultEndpoint == "") {
		return errors.New("The director's default endpoint must either be set to 'cache' or 'origin'." +
		" Was there a typo?")
	}
	engine.Use(director.ShortcutMiddleware(defaultEndpoint))
	director.RegisterDirector(engine.Group("/"))

	log.Info("Starting web engine...")
	go web_ui.RunEngine(engine)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig

	return nil
}
