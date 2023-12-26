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
	"context"
	"embed"
	"fmt"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"golang.org/x/term"
)

var (

	//go:embed frontend/out/*
	webAssets embed.FS
)

func getConfigValues(ctx *gin.Context) {
	user := ctx.GetString("User")
	if user == "" {
		ctx.JSON(401, gin.H{"error": "Authentication required to visit this API"})
		return
	}
	config, err := param.UnmarshalConfig()
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to get the unmarshaled config"})
		return
	}

	ctx.JSON(200, config)
}

func configureWebResource(engine *gin.Engine) error {
	engine.GET("/view/*path", func(ctx *gin.Context) {
		path := ctx.Param("path")

		if strings.HasSuffix(path, "/") {
			path += "index.html"
		}

		db := authDB.Load()
		user, err := getUser(ctx)

		// Redirect initialized users from initialization pages
		if strings.HasPrefix(path, "/initialization") && strings.HasSuffix(path, "index.html") {

			// If the user has been initialized previously
			if db != nil {
				ctx.Redirect(http.StatusFound, "/view/")
				return
			}
		}

		// Redirect authenticated users from login pages
		if strings.HasPrefix(path, "/login") && strings.HasSuffix(path, "index.html") {

			// If the user has been authenticated previously
			if err == nil && user != "" {
				ctx.Redirect(http.StatusFound, "/view/")
				return
			}
		}

		// Direct uninitialized users to initialization pages
		if !strings.HasPrefix(path, "/initialization") && strings.HasSuffix(path, "index.html") {

			// If the user has not been initialized previously
			if db == nil {
				ctx.Redirect(http.StatusFound, "/view/initialization/code/")
				return
			}
		}

		// Direct unauthenticated initialized users to login pages
		if !strings.HasPrefix(path, "/login") && strings.HasSuffix(path, "index.html") {

			// If the user is not authenticated but initialized
			if (err != nil || user == "") && db != nil {
				ctx.Redirect(http.StatusFound, "/view/login/")
				return
			}
		}

		filePath := "frontend/out" + path
		file, _ := webAssets.ReadFile(filePath)
		ctx.Data(
			http.StatusOK,
			mime.TypeByExtension(filePath),
			file,
		)
	})

	engine.GET("/api/v1.0/docs", func(ctx *gin.Context) {

		filePath := "frontend/out/api/docs/index.html"
		file, _ := webAssets.ReadFile(filePath)
		ctx.Data(
			http.StatusOK,
			mime.TypeByExtension(filePath),
			file,
		)
	})

	return nil
}

// Configure common endpoint available to all server web UI which are located at /api/v1.0/*
func configureCommonEndpoints(engine *gin.Engine) error {
	engine.GET("/api/v1.0/config", authHandler, getConfigValues)

	return nil
}

// Configure metrics related endpoints, including Prometheus and /health API
func configureMetrics(engine *gin.Engine) error {
	// Add authorization to /metric endpoint
	engine.Use(promMetricAuthHandler)

	err := ConfigureEmbeddedPrometheus(engine)
	if err != nil {
		return err
	}

	prometheusMonitor := ginprometheus.NewPrometheus("gin")
	prometheusMonitor.Use(engine)

	engine.GET("/api/v1.0/health", authHandler, func(ctx *gin.Context) {
		healthStatus := metrics.GetHealthStatus()
		ctx.JSON(http.StatusOK, healthStatus)
	})
	return nil
}

// Send the one-time code for initial web UI login to stdout and periodically
// re-generate one-time code if user hasn't finished setup
func waitUntilLogin(ctx context.Context) error {
	if authDB.Load() != nil {
		return nil
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	isTTY := false
	if term.IsTerminal(int(os.Stdout.Fd())) {
		isTTY = true
		fmt.Printf("\n\n\n\n")
	}
	activationFile := param.Server_UIActivationCodeFile.GetString()

	defer func() {
		if err := os.Remove(activationFile); err != nil {
			log.Warningf("Failed to remove activation code file (%v): %v\n", activationFile, err)
		}
	}()
	for {
		previousCode.Store(currentCode.Load())
		newCode := fmt.Sprintf("%06v", rand.Intn(1000000))
		currentCode.Store(&newCode)
		newCodeWithNewline := fmt.Sprintf("%v\n", newCode)
		if err := os.WriteFile(activationFile, []byte(newCodeWithNewline), 0600); err != nil {
			log.Errorf("Failed to write activation code to file (%v): %v\n", activationFile, err)
		}

		if isTTY {
			fmt.Printf("\033[A\033[A\033[A\033[A")
			fmt.Printf("\033[2K\n")
			fmt.Printf("\033[2K\rPelican admin interface is not initialized\n\033[2KTo initialize, "+
				"login at \033[1;34mhttps://%v:%v/view/initialization/code/\033[0m with the following code:\n",
				hostname, port)
			fmt.Printf("\033[2K\r\033[1;34m%v\033[0m\n", *currentCode.Load())
		} else {
			fmt.Printf("Pelican admin interface is not initialized\n To initialize, login at https://%v:%v/view/initialization/code/ with the following code:\n", hostname, port)
			fmt.Println(*currentCode.Load())
		}
		start := time.Now()
		for time.Since(start) < 30*time.Second {
			select {
			case <-sigs:
				return errors.New("Process terminated...")
			case <-ctx.Done():
				return nil
			default:
				time.Sleep(100 * time.Millisecond)
			}
			if authDB.Load() != nil {
				return nil
			}
		}
	}
}

// Configure endpoints for server web APIs. This function does not configure any UI
// specific paths but just redirect root path to /view.
//
// You need to mount the static resources for UI in a separate function
func ConfigureServerWebAPI(engine *gin.Engine) error {
	if err := configureAuthEndpoints(engine); err != nil {
		return err
	}
	if err := configureCommonEndpoints(engine); err != nil {
		return err
	}
	if err := configureWebResource(engine); err != nil {
		return err
	}
	if err := configureMetrics(engine); err != nil {
		return err
	}
	// Redirect root to /view for web UI
	engine.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/view/")
	})
	return nil
}

// Setup the initial server web login by sending the one-time code to stdout
// and record health status of the WebUI based on the success of the initialization
func InitServerWebLogin() {
	metrics.SetComponentHealthStatus(metrics.Server_WebUI, metrics.StatusWarning, "Authentication not initialized")

	if err := waitUntilLogin(context.Background()); err != nil {
		log.Errorln("Failure when waiting for web UI to be initialized:", err)
		return
	}
	metrics.SetComponentHealthStatus(metrics.Server_WebUI, metrics.StatusOK, "")
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
	return engine, nil
}

func RunEngine(engine *gin.Engine) {
	certFile := param.Server_TLSCertificate.GetString()
	keyFile := param.Server_TLSKey.GetString()

	addr := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())

	log.Debugln("Starting web engine at address", addr)
	err := engine.RunTLS(addr, certFile, keyFile)
	if err != nil {
		panic(err)
	}
}
