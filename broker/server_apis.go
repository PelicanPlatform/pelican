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
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (

	// Structure for an origin's POST to the broker
	originRequest struct {
		Origin string `json:"origin"`
		Prefix string `json:"prefix"`
	}

	// Response for a successful retrieval
	brokerRetrievalResp struct {
		server_structs.SimpleApiResp
		Request reversalRequest `json:"req"`
	}

	// Structure for an origin calling back to the cache
	callbackRequest struct {
		RequestId string `json:"request_id"`
	}
)

func newBrokerReqResp(req reversalRequest) (result brokerRetrievalResp) {
	result.Request = req
	result.SimpleApiResp.Status = server_structs.RespOK
	return
}

func newBrokerRespFail(msg string) server_structs.SimpleApiResp {
	return server_structs.SimpleApiResp{
		Status: server_structs.RespFailed,
		Msg:    msg,
	}
}

func newBrokerRespTimeout() (result brokerRetrievalResp) {
	result.SimpleApiResp.Status = server_structs.RespPollTimeout
	return
}

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

	token := ginCtx.Request.Header.Get("Authorization")
	token, hasPrefix := strings.CutPrefix(token, "Bearer ")
	if !hasPrefix {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, newBrokerRespFail("Bearer authorization required for callback"))
		return
	}

	ok, err := verifyToken(ctx, token, originReq.Prefix, param.Server_ExternalWebUrl.GetString(), token_scopes.Broker_Retrieve)
	if err != nil {
		log.Errorln("Failed to verify token for reverse request:", err)
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, newBrokerRespFail("Failed to verify provided token"))
		return
	}
	if !ok {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, newBrokerRespFail("Authorization denied"))
	}

	req, err := handleRetrieve(ctx, ginCtx, originReq.Prefix, originReq.Origin, timeoutVal)
	if errors.Is(err, errRetrieveTimeout) {
		ginCtx.JSON(http.StatusOK, newBrokerRespTimeout())
		return
	} else if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, newBrokerRespFail("Failure when retrieving requests for this origin"))
		return
	}

	ginCtx.JSON(http.StatusOK, newBrokerReqResp(req))
}

func reverseRequest(ctx context.Context, ginCtx *gin.Context) {
	timeoutStr := "5s"
	if val := ginCtx.Request.Header.Get("X-Pelican-Timeout"); val != "" {
		timeoutStr = val
	}

	timeoutVal, err := time.ParseDuration(timeoutStr)
	if err != nil {
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, newBrokerRespFail("Failed to parse X-Pelican-Timeout header to a duration (example: 5s)"))
		return
	}

	token := ginCtx.Request.Header.Get("Authorization")
	token, hasPrefix := strings.CutPrefix(token, "Bearer ")
	if !hasPrefix {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, newBrokerRespFail("Bearer authorization required for callback"))
		return
	}

	hostname, err := getCacheHostnameFromToken([]byte(token))
	if err != nil {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, newBrokerRespFail("Failed to determine issuer: "+err.Error()))
		return
	}

	ok, err := verifyToken(ctx, token, server_structs.GetCacheNS(hostname), param.Server_ExternalWebUrl.GetString(), token_scopes.Broker_Reverse)
	if err != nil {
		log.Errorln("Failed to verify token for cache reversal request:", err)
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, newBrokerRespFail("Failed to verify provided token"))
		return
	}
	if !ok {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, newBrokerRespFail("Authorization denied"))
	}

	reversalReq := reversalRequest{}
	if err := ginCtx.Bind(&reversalReq); err != nil {
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, newBrokerRespFail("Failed to parse the cache's reversal request"))
		return
	}
	if reversalReq.OriginName == "" {
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, newBrokerRespFail("Missing 'origin' parameter in request"))
		return
	}
	if reversalReq.Prefix == "" {
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, newBrokerRespFail("Missing 'prefix' parameter in request"))
		return
	}

	if err = handleRequest(ctx, reversalReq.OriginName, reversalReq, timeoutVal); errors.Is(err, errRequestTimeout) {
		ginCtx.AbortWithStatusJSON(http.StatusInternalServerError, newBrokerRespFail("Timeout when waiting for origin callback"))
		return
	} else if err != nil {
		ginCtx.AbortWithStatusJSON(http.StatusInternalServerError, newBrokerRespFail("Failure when waiting for origin callback"))
		return
	}
}

func RegisterBroker(ctx context.Context, router *gin.RouterGroup) {
	// Establish the routes used for cache/origin redirection
	router.POST("/api/v1.0/broker/retrieve", func(ginCtx *gin.Context) { retrieveRequest(ctx, ginCtx) })
	router.POST("/api/v1.0/broker/reverse", func(ginCtx *gin.Context) { reverseRequest(ctx, ginCtx) })
}

// Cache's HTTP handler function for callbacks from an origin
func handleCallback(ctx context.Context, ginCtx *gin.Context) {
	callbackReq := callbackRequest{}
	if err := ginCtx.Bind(&callbackReq); err != nil {
		ginCtx.JSON(http.StatusBadRequest, newBrokerRespFail("Failed to parse the origin's callback request"))
		ginCtx.Abort()
		return
	}

	token := ginCtx.Request.Header.Get("Authorization")
	token, hasPrefix := strings.CutPrefix(token, "Bearer ")
	if !hasPrefix {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, newBrokerRespFail("Bearer authorization required for callback"))
		return
	}

	pendingRev, err := func() (pendingRev pendingReversals, err error) {
		responseMapLock.Lock()
		defer responseMapLock.Unlock()
		pendingRev, ok := response[callbackReq.RequestId]
		if !ok {
			err = errors.Errorf("no such request ID: %q", callbackReq.RequestId)
		}
		return
	}()
	if err != nil {
		ginCtx.JSON(http.StatusBadRequest, newBrokerRespFail("No such request ID"))
		ginCtx.Abort()
		return
	}

	ok, err := verifyToken(ctx, token, pendingRev.prefix, param.Server_ExternalWebUrl.GetString(), token_scopes.Broker_Callback)
	if err != nil {
		log.Errorln("Failed to verify token for cache callback:", err)
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, newBrokerRespFail("Failed to verify provided token"))
		return
	}
	if !ok {
		ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, newBrokerRespFail("Authorization denied"))
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
	case pendingRev.channel <- ginCtx.Writer:
		break
	}

	// Wait for the handler to close the channel, indicating
	// that the TCP connection has been hijacked or an error
	// written back.
	select {
	case <-pendingRev.channel:
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
