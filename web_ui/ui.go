/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"crypto/tls"
	"embed"
	"fmt"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/spf13/viper"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.uber.org/atomic"
	"golang.org/x/sync/errgroup"
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
	rawConfig, err := param.UnmarshalConfig()
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to get the unmarshaled rawConfig"})
		return
	}
	configWithType := param.ConvertToConfigWithType(rawConfig)

	ctx.JSON(200, configWithType)
}

func updateConfigValues(ctx *gin.Context) {
	updatedConfig := param.Config{}
	updatedConfigMap := map[string]interface{}{}

	// Check if the request data is a valid config
	if err := ctx.ShouldBindBodyWith(&updatedConfig, binding.JSON); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to bind the request. Invalid request data format: " + err.Error()})
		return
	}
	if err := ctx.ShouldBindBodyWith(&updatedConfigMap, binding.JSON); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to bind the request into a map: " + err.Error()})
		return
	}

	webConfigPath := param.Server_WebConfigFile.GetString()
	if webConfigPath == "" {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Bad server configuration: Server.WebConfigFile value is empty"})
		return
	}

	// Create a new viper instance to handle config validation and merging
	webCfgViper := viper.New()
	webCfgViper.SetConfigFile(webConfigPath)

	if err := webCfgViper.ReadInConfig(); err != nil {
		log.Error("Failed to read existing web-based config into internal config struct: ", err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read existing web-based config into internal config struct"})
		return
	}

	if err := webCfgViper.MergeConfigMap(updatedConfigMap); err != nil {
		log.Error("Failed to update web-based config with requested changes: ", err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update web-based config with requested changes"})
		return
	}

	if err := webCfgViper.WriteConfig(); err != nil {
		log.Error("Failed to write back the updated config: ", err.Error())
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to write back the updated config"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "success"})
	config.RestartFlag <- true
}

func getEnabledServers(ctx *gin.Context) {
	enabledServers := config.GetEnabledServerString(true)
	if len(enabledServers) == 0 {
		ctx.JSON(500, gin.H{"error": "No enabled servers found"})
		return
	}

	ctx.JSON(200, gin.H{"servers": enabledServers})
}

func configureWebResource(engine *gin.Engine) error {
	engine.GET("/view/*requestPath", func(ctx *gin.Context) {
		requestPath := ctx.Param("requestPath")

		// If the requestPath is a directory indicate that we are looking for the index.html file
		if strings.HasSuffix(requestPath, "/") {
			requestPath += "index.html"
		}

		// Clean the request path
		requestPath = path.Clean(requestPath)

		// If requestPath doesn't have extension, is not a directory, and has a index file, redirect to index file
		if !strings.Contains(requestPath, ".") && !strings.HasSuffix(requestPath, "/") {
			if _, err := webAssets.ReadFile("frontend/out" + requestPath + "/index.html"); err == nil {
				ctx.Redirect(http.StatusMovedPermanently, "/view/"+requestPath+"/")
				return
			}
		}

		db := authDB.Load()
		user, err := GetUser(ctx)

		// If just one server is enabled, redirect to that server
		if len(config.GetEnabledServerString(true)) == 1 && requestPath == "/index.html" {
			ctx.Redirect(http.StatusFound, "/view/"+config.GetEnabledServerString(true)[0]+"/")
			return
		}

		// If requesting servers other than the registry or the director
		if !strings.HasPrefix(requestPath, "/registry") && !strings.HasPrefix(requestPath, "/director") {

			// Redirect initialized users from initialization pages
			if strings.HasPrefix(requestPath, "/initialization") && strings.HasSuffix(requestPath, "index.html") {

				// If the user has been initialized previously
				if db != nil {
					ctx.Redirect(http.StatusFound, "/view/")
					return
				}
			}

			// Redirect authenticated users from login pages
			if strings.HasPrefix(requestPath, "/login") && strings.HasSuffix(requestPath, "index.html") {

				// If the user has been authenticated previously
				if err == nil && user != "" {
					ctx.Redirect(http.StatusFound, "/view/")
					return
				}
			}

			// Direct uninitialized users to initialization pages
			if !strings.HasPrefix(requestPath, "/initialization") && strings.HasSuffix(requestPath, "index.html") {

				// If the user has not been initialized previously
				if db == nil {
					ctx.Redirect(http.StatusFound, "/view/initialization/code/")
					return
				}
			}

			// Direct unauthenticated initialized users to login pages
			if !strings.HasPrefix(requestPath, "/login") && strings.HasSuffix(requestPath, "index.html") {

				// If the user is not authenticated but initialized
				if (err != nil || user == "") && db != nil {
					ctx.Redirect(http.StatusFound, "/view/login/")
					return
				}
			}
		}

		filePath := "frontend/out" + requestPath
		file, _ := webAssets.ReadFile(filePath)

		// If the file is not found, return 404
		if file == nil {
			notFoundFilePath := "frontend/out/404/index.html"
			file, _ := webAssets.ReadFile(notFoundFilePath)
			ctx.Data(
				http.StatusOK,
				mime.TypeByExtension(notFoundFilePath),
				file,
			)
		} else {
			// If the file is found, return the file
			ctx.Data(
				http.StatusOK,
				mime.TypeByExtension(filePath),
				file,
			)
		}
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
	engine.GET("/api/v1.0/config", AuthHandler, AdminAuthHandler, getConfigValues)
	engine.PATCH("/api/v1.0/config", AuthHandler, AdminAuthHandler, updateConfigValues)
	engine.GET("/api/v1.0/servers", getEnabledServers)
	// Health check endpoint for web engine
	engine.GET("/api/v1.0/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Web Engine Running. Time: %s", time.Now().String())})
	})
	return nil
}

// Configure metrics related endpoints, including Prometheus and /health API
func configureMetrics(engine *gin.Engine) error {
	// Add authorization to /metric endpoint
	engine.Use(promMetricAuthHandler)

	prometheusMonitor := ginprometheus.NewPrometheus("gin")
	prometheusMonitor.Use(engine)

	engine.GET("/api/v1.0/metrics/health", AuthHandler, AdminAuthHandler, func(ctx *gin.Context) {
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
func ConfigureServerWebAPI(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) error {
	if err := configureCommonEndpoints(engine); err != nil {
		return err
	}
	if err := configureMetrics(engine); err != nil {
		return err
	}
	if param.Server_EnableUI.GetBool() {
		if err := configureAuthEndpoints(ctx, engine, egrp); err != nil {
			return err
		}
		if err := configureWebResource(engine); err != nil {
			return err
		}
	}

	// Redirect root to /view for web UI
	engine.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/view/")
	})
	return nil
}

// Setup the initial server web login by sending the one-time code to stdout
// and record health status of the WebUI based on the success of the initialization
func InitServerWebLogin(ctx context.Context) error {
	metrics.SetComponentHealthStatus(metrics.Server_WebUI, metrics.StatusWarning, "Authentication not initialized")

	if err := waitUntilLogin(ctx); err != nil {
		log.Errorln("Failure when waiting for web UI to be initialized:", err)
		return err
	}
	metrics.SetComponentHealthStatus(metrics.Server_WebUI, metrics.StatusOK, "")
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
	engine.HandleMethodNotAllowed = true
	return engine, nil
}

// Run the gin engine in the current goroutine.
//
// Will use a background golang routine to periodically reload the certificate
// utilized by the UI.
func RunEngine(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) error {
	return RunEngineRoutine(ctx, engine, egrp, true)
}

// Run the gin engine; if curRoutine is false, it will run in a background goroutine.
func RunEngineRoutine(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, curRoutine bool) error {
	addr := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	config.UpdateConfigFromListener(ln)
	return RunEngineRoutineWithListener(ctx, engine, egrp, curRoutine, ln)
}

// Run the web engine connected to a provided listener `ln`.
func RunEngineRoutineWithListener(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, curRoutine bool, ln net.Listener) error {

	if curRoutine {
		defer ln.Close()
		return runEngineWithListener(ctx, ln, engine, egrp)
	} else {
		egrp.Go(func() error {
			defer ln.Close()
			return runEngineWithListener(ctx, ln, engine, egrp)
		})
		return nil
	}
}

// Run the engine with a given listener.
// This was split out from RunEngine to allow unit tests to provide a Unix domain socket'
// as a listener.
func runEngineWithListener(ctx context.Context, ln net.Listener, engine *gin.Engine, egrp *errgroup.Group) error {
	certFile := param.Server_TLSCertificate.GetString()
	keyFile := param.Server_TLSKey.GetString()

	port := param.Server_WebPort.GetInt()
	addr := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), port)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}

	var certPtr atomic.Pointer[tls.Certificate]
	certPtr.Store(&cert)

	server_utils.LaunchWatcherMaintenance(
		ctx,
		[]string{filepath.Dir(param.Server_TLSCertificate.GetString())},
		"server TLS maintenance",
		2*time.Minute,
		func(notifyEvent bool) error {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				log.Debugln("Loaded new X509 key pair")
				certPtr.Store(&cert)
			} else if notifyEvent {
				log.Debugln("Failed to load new X509 key pair after filesystem event (may succeed eventually):", err)
				return nil
			}
			return err
		},
	)

	getCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certPtr.Load(), nil
	}

	config := &tls.Config{
		GetCertificate: getCert,
	}
	server := &http.Server{
		Addr:      addr,
		Handler:   engine.Handler(),
		TLSConfig: config,
	}
	log.Debugln("Starting web engine at address", addr)

	// Once the context has been canceled, shutdown the HTTPS server.  Give it
	// 10 seconds to shutdown existing requests.
	egrp.Go(func() error {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = server.Shutdown(ctx)
		if err != nil {
			log.Errorln("Failed to shutdown server:", err)
		}
		return err
	})

	if err := server.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
