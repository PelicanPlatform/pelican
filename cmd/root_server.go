//go:build server

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

package main

import (
	"fmt"

	"github.com/pelicanplatform/pelican/launchers"
)

func init() {
	egrpPostHandler = func(err error) (bool, error) {
		if err == launchers.ErrExitOnSignal {
			fmt.Println("Pelican is safely exited")
			return true, nil
		} else if err == launchers.ErrRestart {
			fmt.Println("Restarting server...")
			return true, restartProgram()
		}
		return false, nil
	}
}
