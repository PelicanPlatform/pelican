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

package client_agent

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

// ErrWalletLocked is returned when an operation needs the wallet but it has
// not been opened.
var ErrWalletLocked = errors.New("wallet is locked")

// WalletSession governs the client agent's access to the user's encrypted
// credential file (the "wallet").
//
// The agent never prompts for a password or performs interactive token
// acquisition. Instead the (interactive) CLI warms the wallet with the right
// tokens before submitting a job and hands the agent the wallet password via
// the OpenWallet API. With the wallet open, the agent can decrypt stored
// tokens to authorize transfers and refresh them in the background.
//
// The password is held in the process-wide config keyring (in-memory on most
// platforms, the kernel session keyring on Linux). The wallet file is read
// fresh from disk on each access so updates made by the CLI are visible.
type WalletSession struct {
	mu   sync.Mutex
	open bool
}

// NewWalletSession returns a locked wallet session.
func NewWalletSession() *WalletSession {
	return &WalletSession{}
}

// Open unlocks the wallet using the supplied password, validating it by
// decrypting the credential file. On failure the cached password is cleared.
func (w *WalletSession) Open(password []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	exists, err := config.EncryptedConfigExists()
	if err != nil {
		return errors.Wrap(err, "failed to check for the credential file")
	}
	if !exists {
		return errors.New("no credential file exists yet; acquire credentials before opening the wallet")
	}

	if err := config.SavePassword(password); err != nil {
		return errors.Wrap(err, "failed to cache the wallet password")
	}
	// Validate the password by attempting to decrypt the wallet. For a
	// wallet protected by an empty (unencrypted) key this succeeds for any
	// password; for an encrypted wallet a wrong password yields
	// ErrIncorrectPassword.
	if _, err := config.GetCredentialConfigContents(); err != nil {
		config.ForgetPassword()
		return err
	}
	w.open = true
	return nil
}

// Close locks the wallet, clearing the cached password.
func (w *WalletSession) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	config.ForgetPassword()
	w.open = false
}

// IsOpen reports whether the wallet is currently unlocked.
func (w *WalletSession) IsOpen() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.open
}

// Contents returns the decrypted wallet, read fresh from disk. It returns
// ErrWalletLocked if the wallet has not been opened.
func (w *WalletSession) Contents() (config.CredentialConfig, error) {
	if !w.IsOpen() {
		return config.CredentialConfig{}, ErrWalletLocked
	}
	return config.GetCredentialConfigContents()
}

// --- API types ---

// WalletOpenRequest is the body for POST /wallet/open.
type WalletOpenRequest struct {
	Password string `json:"password"`
}

// WalletStatusResponse is returned by GET /wallet/status and the open/close
// endpoints.
type WalletStatusResponse struct {
	Open                 bool `json:"open"`
	CredentialFileExists bool `json:"credential_file_exists"`
}

// --- handlers ---

// OpenWalletHandler handles POST /api/v1.0/transfer-agent/wallet/open.
// It accepts the wallet password (over the user-owned unix socket) and
// unlocks the wallet so the agent can use and refresh stored credentials.
func (s *Server) OpenWalletHandler(c *gin.Context) {
	var req WalletOpenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  "INVALID_REQUEST",
			Error: "Invalid request body: " + err.Error(),
		})
		return
	}

	if err := s.wallet.Open([]byte(req.Password)); err != nil {
		if errors.Is(err, config.ErrIncorrectPassword) {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Code:  "INCORRECT_PASSWORD",
				Error: "Incorrect wallet password",
			})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:  "WALLET_OPEN_FAILED",
			Error: "Failed to open wallet: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, WalletStatusResponse{Open: true, CredentialFileExists: true})
}

// CloseWalletHandler handles POST /api/v1.0/transfer-agent/wallet/close.
func (s *Server) CloseWalletHandler(c *gin.Context) {
	s.wallet.Close()
	c.JSON(http.StatusOK, WalletStatusResponse{Open: false, CredentialFileExists: walletFileExists()})
}

// WalletStatusHandler handles GET /api/v1.0/transfer-agent/wallet/status.
func (s *Server) WalletStatusHandler(c *gin.Context) {
	c.JSON(http.StatusOK, WalletStatusResponse{
		Open:                 s.wallet.IsOpen(),
		CredentialFileExists: walletFileExists(),
	})
}

// walletFileExists reports whether an encrypted credential file is present,
// swallowing errors (treated as "not present") so status calls never fail.
func walletFileExists() bool {
	exists, err := config.EncryptedConfigExists()
	return err == nil && exists
}
