// web_ui/middleware.go
package web_ui

import (
	"net/http"
	"slices"
	"time"

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func ServerHeaderMiddleware(ctx *gin.Context) {
	ctx.Writer.Header().Add("Server", "pelican/"+config.GetVersion())
}

// ReadOnlyMiddleware blocks unsafe ( state changing ) requests when the server is in read-only mode
var safeMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, "PROPFIND"}

func ReadOnlyMiddleware(ctx *gin.Context) {
	if param.Server_ReadOnly.GetBool() && !slices.Contains(safeMethods, ctx.Request.Method) {
		ctx.JSON(http.StatusMethodNotAllowed, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "The server is in read-only mode and will reject HTTP requests outside of GET, HEAD, OPTIONS, TRACE, and PROPFIND",
		})
		ctx.Abort()
		return
	}
	ctx.Next()
}

func loginRateLimitMiddleware(limit int) gin.HandlerFunc {
	if limit <= 0 {
		log.Warning("Invalid rate limit. Value is less than 1. Fallback to 1")
		limit = 1
	}

	store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  time.Second,
		Limit: uint(limit),
	})

	return ratelimit.RateLimiter(store, &ratelimit.Options{
		ErrorHandler: func(ctx *gin.Context, info ratelimit.Info) {
			ctx.JSON(http.StatusTooManyRequests,
				server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Too many requests. Try again in " + time.Until(info.ResetTime).String(),
				})
		},
		KeyFunc: func(ctx *gin.Context) string { return ctx.ClientIP() },
	})
}
