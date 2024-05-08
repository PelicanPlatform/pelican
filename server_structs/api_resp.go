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

// Package server_structs shares structs and their methods used across multiple server packages (origin/cache/registry/director).
//
// It should only import lower level packages (config/param/etc).
// It should NEVER import any server packages (origin/cache/registry/director) or server_utils package.
//
// For functions used across multiple server packages, put them in server_utils package instead
package server_structs

type (

	// A short response object, meant for the result from most
	// of the Pelican APIs.  Will generate a JSON of the form:
	// {"status": "error", "msg": "Some Error Message"}
	// or
	// {"status": "success"}
	SimpleApiResp struct {
		Status SimpleRespStatus `json:"status"`
		Msg    string           `json:"msg,omitempty"`
	}

	// The standardized status message for the API response
	SimpleRespStatus string
)

const (
	// Indicates the API succeeded.
	RespOK SimpleRespStatus = "success"
	// Indicates the API call failed; the SimpleApiResp Msg should be non-empty in this case
	RespFailed SimpleRespStatus = "error"
	// For long-polling APIs, indicates the requested timeout was hit without any response generated.
	// Should not be considered an error or success but rather indication the long-poll should be retried.
	RespPollTimeout SimpleRespStatus = "timeout"
)
