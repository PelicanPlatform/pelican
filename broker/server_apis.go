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

package broker

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type (

	// Structure for an origin's POST to the broker
	originRequest struct {
		Origin string `json:"origin"`
		Prefix string `json:"prefix"`
	}

	// Structure for an origin retrieval response from the broker
	originResp struct {
		Status  string          `json:"status"`
		Request reversalRequest `json:"request"`
	}

	// Error response for a request or retrieval
	brokerErrResp struct {
		Status string `json:"status"`
		Msg    string `json:"msg"`
	}

	// Structure for an origin calling back to the cache
	callbackRequest struct {
		RequestId string `json:"request_id"`
	}
)

func retrieveRequest(ctx context.Context, ginCtx *gin.Context) {
	timeoutStr := "5s"
	if val := ginCtx.Request.Header.Get("X-Pelican-Timeout"); val != "" {
		timeoutStr = val
	}

	timeoutVal, err := time.ParseDuration(timeoutStr)
	if err != nil {
		ginCtx.String(http.StatusBadRequest, "Failed to parse X-Pelican-Timeout header to a duration (example: 5s)")
		ginCtx.Abort()
		return
	}

	originReq := originRequest{}
	if err := ginCtx.Bind(&originReq); err != nil {
		ginCtx.String(http.StatusBadRequest, "Failed to parse the origin's retrieve request")
		ginCtx.Abort()
		return
	}

	// TODO: check authorization token.

	req, err := handleRetrieve(ctx, ginCtx, originReq.Origin, timeoutVal)
	if errors.Is(err, errRetrieveTimeout) {
		ginCtx.JSON(http.StatusOK, gin.H{"status": "ok", "request": gin.H{}})
		return
	} else if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, brokerErrResp{Status: "error", Msg: "Failure when retrieving requests for this origin"})
		return
	}

	ginCtx.JSON(http.StatusOK, gin.H{"status": "ok", "request": req})
}

func reverseRequest(ctx context.Context, ginCtx *gin.Context) {
	timeoutStr := "5s"
	if val := ginCtx.Request.Header.Get("X-Pelican-Timeout"); val != "" {
		timeoutStr = val
	}

	timeoutVal, err := time.ParseDuration(timeoutStr)
	if err != nil {
		ginCtx.String(http.StatusBadRequest, "Failed to parse X-Pelican-Timeout header to a duration (example: 5s)")
		ginCtx.Abort()
		return
	}

	// TODO: Verify authentication cache token.

	origin, ok := ginCtx.Params.Get("origin")
	if !ok {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"status": "error", "msg": "Missing 'origin' parameter in request"})
		ginCtx.Abort()
		return
	}
	reversalReq := reversalRequest{}
	if err := ginCtx.Bind(&reversalReq); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"status": "error", "msg": "Failed to parse the cache's reversal request"})
		ginCtx.Abort()
		return
	}

	if err = handleRequest(ctx, origin, reversalReq, timeoutVal); errors.Is(err, errRequestTimeout) {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "msg": "Timeout when waiting for origin callback"})
		ginCtx.Abort()
		return
	} else if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"status": "error", "msg": "Failure when waiting for origin callback"})
		ginCtx.Abort()
		return
	}
}

func RegisterBroker(ctx context.Context, router *gin.RouterGroup) {
	// Establish the routes used for cache/origin redirection
	router.POST("/api/v1.0/broker/retrieve", func(ginCtx *gin.Context) { retrieveRequest(ctx, ginCtx) })
	router.POST("/api/v1.0/broker/reverse/:origin", func(ginCtx *gin.Context) { reverseRequest(ctx, ginCtx) })
}

// Cache's HTTP handler function for callbacks from an origin
func handleCallback(ctx context.Context, ginCtx *gin.Context) {
	callbackReq := callbackRequest{}
	if err := ginCtx.Bind(&callbackReq); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"status": "error", "msg": "Failed to parse the origin's callback request"})
		ginCtx.Abort()
		return
	}
	responseChannel, err := func() (responseChannel chan http.ResponseWriter, err error) {
		responseMapLock.Lock()
		defer responseMapLock.Unlock()
		responseChannel, ok := response[callbackReq.RequestId]
		if !ok {
			err = errors.New("no such request ID")
		}
		return
	}()

	if err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"status": "error", "msg": "No such request ID"})
		ginCtx.Abort()
		return
	}

	// Pass the response writer to the handler (or wait for
	// a context cancel)
	select {
	case <-ctx.Done():
		ginCtx.AbortWithStatus(http.StatusBadGateway)
		return
	case <-ginCtx.Done():
		ginCtx.AbortWithStatus(http.StatusBadGateway)
		return
	case responseChannel <- ginCtx.Writer:
		break
	}

	// Wait for the handler to close the channel, indicating
	// that the TCP connection has been hijacked or an error
	// written back.
	select {
	case <-responseChannel:
		return
	case <-ctx.Done():
		return
	case <-ginCtx.Done():
		return
	}
}

// Register the HTTP handlers for the callback to a cache
func RegisterBrokerCallback(ctx context.Context, router *gin.RouterGroup) {
	router.POST("/api/v1.0/broker/callback", func(ginCtx *gin.Context) { handleCallback(ctx, ginCtx) })
}
