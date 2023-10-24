/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package web_ui

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	ginprometheus "github.com/zsais/go-gin-prometheus"
)

func ConfigureMetrics(engine *gin.Engine, isDirector bool) error {
	err := ConfigureEmbeddedPrometheus(engine, isDirector)
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
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return nil, errors.New(fmt.Sprintln("Failed to retrieve caller information"))
	}

	callerChain := strings.Split(runtime.FuncForPC(pc).Name(), ".") // get the function name
	// We only care about one level up caller
	callerName := callerChain[len(callerChain)-1]

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
	// We configure Prometheus differently for director than for the rest servers,
	// although in the future we probably want to pass the server type to the
	// metric config function just because each server may have different config
	if err := ConfigureMetrics(engine, callerName == "serveDirector"); err != nil {
		return nil, err
	}
	return engine, nil
}

func RunEngine(engine *gin.Engine) {
	certFile := param.Server_TLSCertificate.GetString()
	keyFile := param.Server_TLSKey.GetString()

	addr := fmt.Sprintf("%v:%v", param.Server_Address.GetString(), param.Server_Port.GetInt())

	log.Debugln("Starting web engine at address", addr)
	err := engine.RunTLS(addr, certFile, keyFile)
	if err != nil {
		panic(err)
	}
}
