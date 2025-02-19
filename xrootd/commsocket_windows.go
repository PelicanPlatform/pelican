//go:build windows

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

package xrootd

import (
	"os"

	"github.com/pkg/errors"
)

// Set the origin's FDs; not implemented on Windows
func setOriginFds([2]int) {}

// Set the cache's FDs; not implemented on Windows
func setCacheFds([2]int) {}

// Send a provided file descriptor to a child xrootd process; not implemented on Windows
func sendChildFD(bool, int, *os.File) error {
	return errors.New("sendChildFD not implemented on Windows")
}

// Close the child socket; not implemented on Windows
func closeChildSocket(origin bool) error {
	return errors.New("closeChildSocket not implemented on Windows")
}
