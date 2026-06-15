/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

// Package transfer implements the transfer server module which exposes the
// client_agent transfer APIs over HTTP with JWT-based authentication,
// credential management, and per-user job ownership.
package transfer

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oauth2/issuer"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

// allowedPrefixes, when non-empty, restricts submitted transfers so that
// every transfer item's source or destination path must fall under one of
// these federation prefixes.  This is set when the transfer API runs
// inside an origin server.
var allowedPrefixes []string

// RegisterTransferAPI registers the transfer API routes on the given gin engine.
// It sets up the transfer manager for job execution and wires all API handlers.
func RegisterTransferAPI(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) error {
	db := database.ServerDatabase
	if db == nil {
		return errors.New("server database not initialized; cannot register transfer API")
	}

	maxJobs := param.Transfer_MaxConcurrentJobs.GetInt()
	if maxJobs <= 0 {
		maxJobs = 5
	}

	// Create a transfer manager using the server database's store adapter
	tm := client_agent.NewTransferManager(ctx, maxJobs, nil)

	return registerTransferRoutes(ctx, engine, egrp, db, tm)
}

// RegisterLocalIssuer stands up the server-level "local" OIDC issuer used to
// authenticate clients to a standalone transfer server (one with no co-located
// origin or director). It registers a single provider whose tokens carry
// iss = config.GetLocalIssuerUrl() and the (group-gated) pelican.transfer
// scope, exposing its OIDC discovery, dynamic-client-registration, device-code,
// and token endpoints under /api/v1.0/issuer/ns/.transfer. A co-located
// transfer server instead obtains the local issuer through the origin's
// embedded-issuer setup, so this must only be called on standalone servers to
// avoid duplicate route registration.
func RegisterLocalIssuer(ctx context.Context, egrp *errgroup.Group, engine *gin.Engine, db *gorm.DB) error {
	gracePeriod := param.Issuer_RefreshTokenGracePeriod.GetDuration()
	if gracePeriod == 0 {
		gracePeriod = 5 * time.Minute
	}

	registry := issuer.NewProviderRegistry()
	if err := issuer.RegisterLocalProvider(ctx, egrp, registry, db, gracePeriod); err != nil {
		return errors.Wrap(err, "failed to register local transfer issuer provider")
	}

	// Non-aborting middleware so issuer handlers (e.g. device-verify) can see
	// the identity from the login cookie without rejecting unauthenticated
	// requests outright.
	issuer.RegisterRoutesWithMiddleware(engine, registry, func(c *gin.Context) {
		user, userId, groups, _ := web_ui.GetUserGroups(c)
		if user != "" {
			c.Set("User", user)
			if userId != "" {
				c.Set("UserId", userId)
			}
			if len(groups) > 0 {
				c.Set("Groups", groups)
			}
		}
		c.Next()
	})
	issuer.RegisterAdminRoutes(engine, registry, web_ui.AuthHandler, web_ui.AdminAuthHandler)

	log.Info("Transfer server local issuer configured")
	return nil
}

// RegisterTransferAPIForOrigin registers the transfer API routes when running
// within an origin server. This is called when Origin.EnableTransferAPI is true.
// Transfers are scoped to the origin's federation prefixes: every submitted
// transfer must have its source or destination under one of the origin's
// exported namespaces.
func RegisterTransferAPIForOrigin(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group) error {
	if !param.Origin_EnableTransferAPI.GetBool() {
		return nil
	}

	// Collect the origin's federation prefixes for transfer path validation
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		return errors.Wrap(err, "failed to get origin exports for transfer API")
	}
	prefixes := make([]string, 0, len(exports))
	for _, export := range exports {
		if export.FederationPrefix != "" {
			prefixes = append(prefixes, export.FederationPrefix)
		}
	}
	if len(prefixes) == 0 {
		log.Warn("Origin has no federation prefixes; transfer API will reject all jobs")
	}
	allowedPrefixes = prefixes

	// Ensure the transfer tables exist
	if err := InitTransferDatabase(); err != nil {
		return errors.Wrap(err, "failed to initialize transfer database for origin")
	}

	log.Infof("Enabling transfer API on origin (allowed prefixes: %s)", strings.Join(prefixes, ", "))
	if err := RegisterTransferAPI(ctx, engine, egrp); err != nil {
		return err
	}

	LaunchCredentialCleanup(ctx, egrp)
	return nil
}

// registerTransferRoutes sets up all the route handlers
func registerTransferRoutes(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, db *gorm.DB, tm *client_agent.TransferManager) error {
	// Public (unauthenticated) endpoints
	publicGroup := engine.Group("/api/v1.0/transfer", web_ui.ServerHeaderMiddleware)
	{
		publicGroup.GET("/ping", handlePing())
	}

	// Shared OAuth2 callback endpoint — multiple modules can register
	// handlers here, dispatched by state-parameter prefix.
	callbackGroup := engine.Group(SharedCallbackPath, web_ui.ServerHeaderMiddleware)
	{
		callbackGroup.GET("", HandleSharedCallback(db))
		callbackGroup.GET("/start/:code", handleStartRedirect())
	}

	// Authenticated endpoints
	transferGroup := engine.Group("/api/v1.0/transfer", web_ui.ServerHeaderMiddleware)
	transferGroup.Use(TransferAuthMiddleware(db))
	{
		// Credential bootstrap discovery. Authenticated (and gated to
		// registered issuers) because it triggers a server-side fetch of a
		// user-supplied issuer URL.
		transferGroup.GET("/auth-methods", handleGetAuthMethods(db))

		// Credential management
		transferGroup.POST("/credentials", handleCreateCredential(db))
		transferGroup.GET("/credentials", handleListCredentials(db))
		transferGroup.GET("/credentials/:id", handleGetCredential(db))
		transferGroup.DELETE("/credentials/:id", handleDeleteCredential(db))

		// Credential bootstrap
		transferGroup.POST("/credentials/bootstrap/token-exchange", handleTokenExchangeBootstrap(db))
		transferGroup.POST("/credentials/bootstrap/authcode", handleAuthCodeBootstrapStart(db))
		transferGroup.GET("/credentials/bootstrap/authcode/:session_id", handleAuthCodeBootstrapPoll(db))

		// OAuth2 client management
		transferGroup.POST("/oauth-clients", handleCreateOAuthClient(db))
		transferGroup.GET("/oauth-clients", handleListOAuthClients(db))
		transferGroup.DELETE("/oauth-clients/:id", handleDeleteOAuthClient(db))

		// Transfer job management
		transferGroup.POST("/jobs", handleCreateTransferJob(db, tm))
		transferGroup.GET("/jobs", handleListTransferJobs(db, tm))
		transferGroup.GET("/jobs/:job_id", handleGetTransferJob(db, tm))
		transferGroup.DELETE("/jobs/:job_id", handleCancelTransferJob(db, tm))
	}

	// Start bootstrap session cleanup
	LaunchBootstrapSessionCleanup(ctx, egrp)

	return nil
}

// InitTransferDatabase ensures the server database is initialized with transfer
// support. This is typically called during the launcher sequence before routes
// are registered.
func InitTransferDatabase() error {
	dbPath := param.Transfer_DbLocation.GetString()
	if dbPath == "" {
		dbPath = param.Server_DbLocation.GetString()
	}
	log.Debugf("Transfer module using database: %s", dbPath)

	// The server database should already be initialized by the launcher.
	// We just verify the connection and that our tables exist.
	if database.ServerDatabase == nil {
		return errors.New("server database is not initialized")
	}

	// Verify our tables exist (they should have been created by goose migrations)
	if err := database.ServerDatabase.Exec("SELECT 1 FROM transfer_credentials LIMIT 0").Error; err != nil {
		return errors.Wrap(err, "transfer_credentials table not found; migration may not have run")
	}

	return nil
}

// LaunchCredentialCleanup starts a background goroutine that periodically
// removes credentials that have not been used within the configured idle timeout.
func LaunchCredentialCleanup(ctx context.Context, egrp *errgroup.Group) {
	timeout := param.Transfer_CredentialIdleTimeout.GetDuration()
	if timeout <= 0 {
		log.Info("Transfer credential idle cleanup disabled (timeout <= 0)")
		return
	}

	egrp.Go(func() error {
		return runCredentialCleanup(ctx, database.ServerDatabase, timeout)
	})
}

// runCredentialCleanup periodically removes idle credentials
func runCredentialCleanup(ctx context.Context, db *gorm.DB, timeout time.Duration) error {
	// Run cleanup at an interval of half the timeout, but at least once per minute
	// and at most once per hour.
	interval := timeout / 2
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > time.Hour {
		interval = time.Hour
	}

	log.Infof("Transfer credential cleanup running with idle timeout %v, check interval %v", timeout, interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cutoff := time.Now().Add(-timeout)

			// Delete credentials that have been used but not within the timeout,
			// or that have never been used and were created before the cutoff.
			result := db.Where(
				"(last_used_at IS NOT NULL AND last_used_at < ?) OR (last_used_at IS NULL AND created_at < ?)",
				cutoff, cutoff,
			).Delete(&TransferCredential{})

			if result.Error != nil {
				log.Errorf("Transfer credential cleanup error: %v", result.Error)
			} else if result.RowsAffected > 0 {
				log.Infof("Transfer credential cleanup removed %d idle credential(s)", result.RowsAffected)
			}
		}
	}
}
