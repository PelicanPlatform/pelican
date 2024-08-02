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
	"net/http/pprof"

	"github.com/gin-gonic/gin"
)

// Setup endpoints for pprof https://pkg.go.dev/runtime/pprof
func configurePprof(router *gin.Engine) {
	pprofRoutes := router.Group("/api/v1.0/debug/pprof", AuthHandler, AdminAuthHandler)
	{
		pprofRoutes.GET("/", gin.WrapF(pprof.Index))
		pprofRoutes.GET("/cmdline", gin.WrapF(pprof.Cmdline))
		pprofRoutes.GET("/profile", gin.WrapF(pprof.Profile))
		pprofRoutes.POST("/symbol", gin.WrapF(pprof.Symbol))
		pprofRoutes.GET("/symbol", gin.WrapF(pprof.Symbol))
		pprofRoutes.GET("/trace", gin.WrapF(pprof.Trace))
		pprofRoutes.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
		pprofRoutes.GET("/block", gin.WrapH(pprof.Handler("block")))
		pprofRoutes.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
		pprofRoutes.GET("/heap", gin.WrapH(pprof.Handler("heap")))
		pprofRoutes.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
		pprofRoutes.GET("/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))
	}
}
