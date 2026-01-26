//go:build windows

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
	"os"
	"time"

	"github.com/pkg/errors"
)

// DaemonConfig holds configuration for daemon mode
// On Windows, daemon mode is not supported, but we keep the struct
// for API compatibility with Unix systems
type DaemonConfig struct {
	SocketPath  string
	PidFile     string
	LogLocation string
	MaxJobs     int
	DbLocation  string
	IdleTimeout time.Duration
}

// StartDaemon is not supported on Windows
// The server must run in foreground mode on Windows
func StartDaemon(config DaemonConfig) (int, error) {
	return 0, errors.New("daemon mode is not supported on Windows; use --foreground flag")
}

// IsDaemonMode always returns false on Windows
func IsDaemonMode() bool {
	return false
}

// InheritDaemonLock is not supported on Windows
func InheritDaemonLock() (*os.File, error) {
	return nil, errors.New("daemon lock inheritance is not supported on Windows")
}
