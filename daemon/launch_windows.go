//go:build windows

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package daemon

import (
	"context"
	"io"

	"github.com/pkg/errors"
)

func LaunchDaemons(launchers []Launcher) (err error) {
	return errors.New("launching daemons is not supported on Windows")
}

func (launcher DaemonLauncher) Launch(ctx context.Context) (context.Context, int, error) {
	return context.Background(), -1, errors.New("launching daemons is not supported on Windows")
}

func ForwardCommandToLogger(ctx context.Context, daemonName string, cmdStdout io.ReadCloser, cmdStderr io.ReadCloser) {
	return
}
