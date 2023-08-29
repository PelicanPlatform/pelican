package main

import (
	"os"
	"os/signal"
	"syscall"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/namespace-registry"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)


func serveNamespaceRegistry( /*cmd*/ *cobra.Command /*args*/, []string) error {
	log.Info("Initializing the namespace registry's database...")

	// Initialize the registry's sqlite database
	err := nsregistry.InitializeDB()
	if err != nil {
		return errors.Wrapf(err, "Unable to initialize the namespace registry database: %q")
	}

	// function defined in director_serve
	err = generateTLSCertIfNeeded()
	if err != nil {
		return errors.Wrapf(err, "Failed to generate TLS certificate: %q")
	}

	engine, err := web_ui.GetEngine()
	if err != nil {
		return err
	}

	// Call out to nsregistry to establish routes for the gin engine
	nsregistry.RegisterNamespaceRegistry(engine.Group("/"))
	log.Info("Starting web engine...")

	// Might need to play around with this setting more to handle
	// more complicated routing scenarios where we can't just use
	// a wildcard. It removes duplicate / from the resource.
	//engine.RemoveExtraSlash = true
	go web_ui.RunEngine(engine)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigs
	_ = sig

	return nil
}
