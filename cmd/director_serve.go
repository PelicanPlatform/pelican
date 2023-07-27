package main

import (
	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/director"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	gin.SetMode(gin.ReleaseMode)
	cacheEngine := gin.Default()

	// Use the shortcut middleware so that GET /foo/bar
	// acts the same as GET /api/v1.0/director/object/foo/bar
	cacheEngine.Use(director.ShortcutMiddleware())
	director.RegisterDirector(cacheEngine.Group("/"))

	// serve the Director on specified port
	port := viper.GetString("port")
	log.Info("Serving director on port", port)
	err := cacheEngine.Run(":" + port)
	if err != nil {
		panic(err)
	}

	return nil
}
