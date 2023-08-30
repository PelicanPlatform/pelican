package web_ui

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/metrics"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/zsais/go-gin-prometheus"
)

func ConfigureMetrics(engine *gin.Engine) error {
	err := ConfigureEmbeddedPrometheus(engine)
	if err != nil {
		return err
	}

	prometheusMonitor := ginprometheus.NewPrometheus("gin")
	prometheusMonitor.Use(engine)

	engine.GET("/api/v1.0/health", func(ctx *gin.Context) {
		healthStatus := metrics.GetHealthStatus()
		ctx.JSON(http.StatusOK, healthStatus)
	})
	return nil
}

func GetEngine() (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	webLogger := log.WithFields(log.Fields{"daemon": "gin"})
	engine.Use(func(ctx *gin.Context) {
		startTime := time.Now()

		ctx.Next()

		latency := time.Since(startTime)
		webLogger.WithFields(log.Fields{"method": ctx.Request.Method,
			"status":   ctx.Writer.Status(),
			"time":     latency.String(),
			"client":   ctx.RemoteIP(),
			"resource": ctx.Request.URL.Path},
		).Info("Served Request")
	})
	if err := ConfigureMetrics(engine); err != nil {
		return nil, err
	}
	return engine, nil
}

func RunEngine(engine *gin.Engine) {
	certFile := viper.GetString("TLSCertificate")
	keyFile := viper.GetString("TLSKey")

	addr := fmt.Sprintf("%v:%v", viper.GetString("WebAddress"), viper.GetInt("WebPort"))

	err := engine.RunTLS(addr, certFile, keyFile)
	if err != nil {
		panic(err)
	}
}
