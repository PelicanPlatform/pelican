// web_ui/middleware.go
package web_ui

import (
	"net/http"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// loginRateLimitStores caches one rate-limit store per limit value.
// gin-rate-limit's InMemoryStore starts a background cleanup goroutine that it
// never stops, and RegisterAuthEndpoints runs on every web-engine launch, so a
// fresh store per call would leak a goroutine each time. Reuse one store per
// limit for the lifetime of the process instead.
var (
	loginRateLimitStores   = map[int]ratelimit.Store{}
	loginRateLimitStoresMu sync.Mutex
)

func loginRateLimitStore(limit int) ratelimit.Store {
	loginRateLimitStoresMu.Lock()
	defer loginRateLimitStoresMu.Unlock()
	if store, ok := loginRateLimitStores[limit]; ok {
		return store
	}
	store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  time.Second,
		Limit: uint(limit),
	})
	loginRateLimitStores[limit] = store
	return store
}

func ServerHeaderMiddleware(ctx *gin.Context) {
	ctx.Writer.Header().Add("Server", "pelican/"+config.GetVersion())
}

// rejectInvalidPathMiddleware rejects requests whose URL path is not valid
// UTF-8 before they reach any downstream handler or metrics middleware. Such
// paths (e.g. overlong UTF-8 encodings) are malformed and would otherwise
// panic Prometheus label collection, which requires valid UTF-8 strings.
// Rather than silently sanitizing the path and passing the request through,
// we reject it with HTTP 400 Bad Request. RawPath is only checked when
// non-empty; per Go's net/url documentation, RawPath is only set when the
// encoded form of Path differs from the default encoding, so it is typically
// empty.
func rejectInvalidPathMiddleware(ctx *gin.Context) {
	if !utf8.ValidString(ctx.Request.URL.Path) ||
		(ctx.Request.URL.RawPath != "" && !utf8.ValidString(ctx.Request.URL.RawPath)) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "The request path contains invalid UTF-8 characters",
		})
		ctx.Abort()
		return
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

	store := loginRateLimitStore(limit)

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
