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

package config

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestLoggingFilter(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.DebugLevel)
	logger.AddHook(globalTransform)
	hook := test.NewLocal(logger)

	// Actual log message observed; note this token is expired and hence useless
	message := `240229 14:13:55 18544 XrdPfc_Cache: info Attach() pelican://u221@itb-osdf-director-origins.dev.osgdev.chtc.io:443//ospool/ap20/data/dvp2/singularity_repos/iebe-music_dev.sif?&authz=Bearer%20eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjhiNjkifQ.eyJzdWIiOiJkdnAyIiwic2NvcGUiOiJyZWFkOi9kYXRhL2R2cDIgd3JpdGU6L2RhdGEvZHZwMiIsInZlciI6InNjaXRva2VuczoyLjAiLCJhdWQiOlsiQU5ZIl0sImlzcyI6Imh0dHBzOi8vYXAyMC51Yy5vc2ctaHRjLm9yZzoxMDk0L29zcG9vbC9hcDIwIiwiZXhwIjoxNzA5MjM4MTk3LCJpYXQiOjE3MDkyMzY5OTcsIm5iZiI6MTcwOTIzNjk5NywianRpIjoiNGNhNGM0NmItZDBiNy00YTFhLTk4NmYtYzk0Mjc1MzAzNDc3In0.ImFc2WiTLJDjavsjDQWgVJhASAkmV-XE2LbJkogv_kjxdF0sazTKPPRqaLmQ7_Tab-1nDYixfHT58CmFLHeebQ`
	logger.Error(message)

	assert.Equal(t, 1, len(hook.Entries))
	assert.Equal(t, log.ErrorLevel, hook.LastEntry().Level)
	assert.Equal(t, `240229 14:13:55 18544 XrdPfc_Cache: info Attach() pelican://u221@itb-osdf-director-origins.dev.osgdev.chtc.io:443//ospool/ap20/data/dvp2/singularity_repos/iebe-music_dev.sif?&authz=Bearer%20eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjhiNjkifQ.eyJzdWIiOiJkdnAyIiwic2NvcGUiOiJyZWFkOi9kYXRhL2R2cDIgd3JpdGU6L2RhdGEvZHZwMiIsInZlciI6InNjaXRva2VuczoyLjAiLCJhdWQiOlsiQU5ZIl0sImlzcyI6Imh0dHBzOi8vYXAyMC51Yy5vc2ctaHRjLm9yZzoxMDk0L29zcG9vbC9hcDIwIiwiZXhwIjoxNzA5MjM4MTk3LCJpYXQiOjE3MDkyMzY5OTcsIm5iZiI6MTcwOTIzNjk5NywianRpIjoiNGNhNGM0NmItZDBiNy00YTFhLTk4NmYtYzk0Mjc1MzAzNDc3In0.REDACTED`, hook.LastEntry().Message)
}
