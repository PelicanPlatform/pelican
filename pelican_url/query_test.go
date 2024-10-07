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

package pelican_url

import (
	"testing"
)

func TestValidateQueryParams(t *testing.T) {
	tests := []struct {
		name         string
		pUrl         string
		allowUnknown bool
		expected     string
		errMsg       string
	}{
		{
			name:         "test valid recursive",
			pUrl:         "pelican://something/here?recursive",
			allowUnknown: false,
			expected:     "recursive",
			errMsg:       "",
		},
		{
			name:         "test valid directread",
			pUrl:         "pelican://something/here?directread",
			allowUnknown: false,
			expected:     "directread",
			errMsg:       "",
		},
		{
			name:         "test valid skipstat",
			pUrl:         "pelican://something/here?skipstat",
			allowUnknown: false,
			expected:     "skipstat",
			errMsg:       "",
		},
		{
			name:         "test valid prefercached",
			pUrl:         "pelican://something/here?prefercached",
			allowUnknown: false,
			expected:     "prefercached",
			errMsg:       "",
		},
		{
			name:         "test valid pack auto",
			pUrl:         "pelican://something/here?pack=auto",
			allowUnknown: false,
			expected:     "pack=auto",
			errMsg:       "",
		},
		{
			name:         "test valid pack tar",
			pUrl:         "pelican://something/here?pack=tar",
			allowUnknown: false,
			expected:     "pack=tar",
			errMsg:       "",
		},
		{
			name:         "test valid pack tar.gz",
			pUrl:         "pelican://something/here?pack=tar.gz",
			allowUnknown: false,
			expected:     "pack=tar.gz",
			errMsg:       "",
		},
		{
			name:         "test valid pack tar.xz",
			pUrl:         "pelican://something/here?pack=tar.xz",
			allowUnknown: false,
			expected:     "pack=tar.xz",
			errMsg:       "",
		},
		{
			name:         "test valid pack zip",
			pUrl:         "pelican://something/here?pack=zip",
			allowUnknown: false,
			expected:     "pack=zip",
			errMsg:       "",
		},
		{
			name:         "test no pack value",
			pUrl:         "pelican://something/here?pack",
			allowUnknown: false,
			expected:     "",
			errMsg:       "Missing value for query parameter 'pack'",
		},
		{
			name:         "test invalid pack value",
			pUrl:         "pelican://something/here?pack=foobar",
			allowUnknown: false,
			expected:     "",
			errMsg:       "Invalid value for query parameter 'pack': foobar",
		},
		{
			name:         "test unrecognized, don't allow unknown",
			pUrl:         "pelican://something/here?somethingrandom",
			allowUnknown: false,
			expected:     "",
			errMsg:       "Unknown query parameter 'somethingrandom'",
		},
		{
			name:         "test unrecognized, do allow unknown",
			pUrl:         "pelican://something/here?somethingrandom",
			allowUnknown: true,
			expected:     "somethingrandom",
			errMsg:       "",
		},
		{
			name:         "test unrecognized, do allow unknown with multi-valued query",
			pUrl:         "pelican://something/here?somethingrandom=foo&somethingrandom=bar",
			allowUnknown: true,
			expected:     "somethingrandom=foo&somethingrandom=bar",
			errMsg:       "",
		},
		{
			name:         "test chained query",
			pUrl:         "pelican://something/here?directread&recursive",
			allowUnknown: false,
			expected:     "directread&recursive",
			errMsg:       "",
		},
		{
			name:         "test pack and recursive together disallowed",
			pUrl:         "pelican://something/here?pack=auto&recursive",
			allowUnknown: false,
			expected:     "",
			errMsg:       "Cannot have both 'recursive' and 'pack' query parameters",
		},
		{
			name:         "test prefercached and directread together disallowed",
			pUrl:         "pelican://something/here?prefercached&directread",
			allowUnknown: false,
			expected:     "",
			errMsg:       "Cannot have both 'directread' and 'prefercached' query parameters",
		},
	}

	for _, tt := range tests {
		pUrl, err := Parse(tt.pUrl, []ParseOption{AllowUnknownQueryParams(tt.allowUnknown), ValidateQueryParams(true)}, nil)
		if tt.expected != "" {
			if pUrl.RawQuery != tt.expected {
				t.Errorf("expected query '%s', got '%s'", tt.expected, pUrl.RawQuery)
			}
		} else if tt.errMsg != "" {
			if err == nil {
				t.Errorf("expected error '%s', got nil", tt.errMsg)
			} else if err.Error() != tt.errMsg {
				t.Errorf("expected error '%s', got '%s'", tt.errMsg, err.Error())
			}
		}
	}
}
