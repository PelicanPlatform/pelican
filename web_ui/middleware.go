// web_ui/middleware.go
package web_ui

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func ServerHeaderMiddleware(ctx *gin.Context) {
	ctx.Writer.Header().Add("Server", "pelican/"+config.GetVersion())
	ctx.Next()
}

// ReadOnlyMiddleware blocks unsafe ( non-state changing ) requests when the server is in read-only mode
var safeMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace}

func ReadOnlyMiddleware(ctx *gin.Context) {
	if param.Server_ReadOnly.GetBool() && !slices.Contains(safeMethods, ctx.Request.Method) {
		ctx.JSON(http.StatusServiceUnavailable, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "The server is in read-only mode and will reject HTTP requests outside of GET, HEAD, OPTIONS, and TRACE",
		})
		ctx.Abort()
		return
	}
	ctx.Next()
}
