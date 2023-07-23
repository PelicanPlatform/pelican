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
	if err := director.AdvertiseOSDF(); err != nil {
		panic(err)
	}

	gin.SetMode(gin.ReleaseMode)
	cacheEngine := gin.Default()
	director.RegisterDirector(cacheEngine.Group("/"))

	// Eventually we'll want a redirect-to-origin service split off
	// on another port. Can we use a groutine to handle that here?
	cachePort := viper.GetString("cachePort")
	//originPort := viper.GetString("originPort")
	log.Info("Serving cache redirector on port", cachePort)
	err := cacheEngine.Run(":" + cachePort)
	if err != nil {
		panic(err)
	}

	return nil
}
