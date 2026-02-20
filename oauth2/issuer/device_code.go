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

package issuer

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// DeviceCodeHandler implements the OAuth 2.0 Device Authorization Grant (RFC 8628).
type DeviceCodeHandler struct {
	storage *OIDCStorage
	config  *fosite.Config
}

// NewDeviceCodeHandler creates a new device code handler.
func NewDeviceCodeHandler(storage *OIDCStorage, config *fosite.Config) *DeviceCodeHandler {
	return &DeviceCodeHandler{
		storage: storage,
		config:  config,
	}
}

// DeviceAuthorizationResponse is the response from the device authorization endpoint.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

// HandleDeviceAuthorizationRequest creates a new device code session.
func (h *DeviceCodeHandler) HandleDeviceAuthorizationRequest(ctx context.Context,
	client fosite.Client, scopes []string) (*DeviceAuthorizationResponse, error) {

	if client == nil {
		return nil, fosite.ErrInvalidClient
	}

	deviceCode, err := generateSecureToken(32)
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug("Failed to generate device code")
	}

	userCode, err := generateUserCode()
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug("Failed to generate user code")
	}

	request := fosite.NewRequest()
	request.RequestedAt = time.Now()
	request.Client = client
	request.RequestedScope = scopes
	request.GrantedScope = scopes

	expiresIn := 10 * time.Minute
	expiresAt := time.Now().Add(expiresIn)

	if err := h.storage.CreateDeviceCodeSession(ctx, deviceCode, userCode, request, expiresAt); err != nil {
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug("Failed to store device code")
	}

	verificationURI := h.config.AccessTokenIssuer + "/api/v1.0/issuer/device"

	return &DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: fmt.Sprintf("%s?user_code=%s", verificationURI, userCode),
		ExpiresIn:               int(expiresIn.Seconds()),
		Interval:                5,
	}, nil
}

// HandleDeviceAccessRequest validates and returns the approved device code request.
func (h *DeviceCodeHandler) HandleDeviceAccessRequest(ctx context.Context,
	deviceCode string, session fosite.Session) (fosite.Requester, error) {

	request, err := h.storage.GetDeviceCodeSession(ctx, deviceCode, session)
	if err != nil {
		return nil, err
	}

	// Mark as used
	_ = h.storage.InvalidateDeviceCodeSession(ctx, deviceCode)

	return request, nil
}

func generateSecureToken(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}

func generateUserCode() (string, error) {
	// Use unambiguous alphanumeric characters in XXXX-XXXX format
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const codeLen = 8
	const groupSize = 4

	var code strings.Builder
	for i := 0; i < codeLen; i++ {
		if i > 0 && i%groupSize == 0 {
			code.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		code.WriteByte(charset[n.Int64()])
	}
	return code.String(), nil
}
