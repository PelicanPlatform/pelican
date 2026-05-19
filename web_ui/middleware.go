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
	"github.com/pelicanplatform/pelican/utils"
)

func ServerHeaderMiddleware(ctx *gin.Context) {
	ctx.Writer.Header().Add("Server", "pelican/"+config.GetVersion())
}

// sanitizePathMiddleware sanitizes the request URL path before it reaches any
// downstream handler or metrics middleware. Any non-UTF-8 byte sequences in
// the path are replaced with the Unicode replacement character (U+FFFD). This
// prevents panics in Prometheus label collection, which requires valid UTF-8
// strings. RawPath is only sanitized when non-empty; per Go's net/url
// documentation, RawPath is only set when the encoded form of Path differs
// from the default encoding, so it is typically empty.
func sanitizePathMiddleware(ctx *gin.Context) {
	ctx.Request.URL.Path = utils.EnsureValidUTF8(ctx.Request.URL.Path)
	if ctx.Request.URL.RawPath != "" {
		ctx.Request.URL.RawPath = utils.EnsureValidUTF8(ctx.Request.URL.RawPath)
	}
	ctx.Next()
}

// ReadOnlyMiddleware blocks unsafe ( state changing ) requests when the server is in read-only mode
var safeMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, "PROPFIND"}

func ReadOnlyMiddleware(ctx *gin.Context) {
	if param.Server_WebReadOnly.GetBool() && !slices.Contains(safeMethods, ctx.Request.Method) {
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
