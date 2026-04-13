//go:build client

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

import "strings"

func init() {
	cliDispatchHook = func(execName string, args []string) (bool, error) {
		if strings.HasPrefix(execName, "stash_plugin") ||
			strings.HasPrefix(execName, "osdf_plugin") ||
			strings.HasPrefix(execName, "pelican_xfer_plugin") ||
			strings.HasPrefix(execName, "pelican_plugin") {
			stashPluginMain(args[1:])
			return true, nil
		}
		if strings.HasPrefix(execName, "stashcp") {
			return true, copyCmd.Execute()
		}
		return false, nil
	}
}
