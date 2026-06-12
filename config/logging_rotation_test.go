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

package config

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
)

// TestFileLoggingThroughRedactionFilter is the belt-and-suspenders check that the
// asynchronous, rotating file writer is correctly wired as the sink for the
// redaction/filter hook path used in production.
//
// It mirrors the production init order (FlushLogs(true) installs the async file
// writer as the logrus output, then initFilterLogging() captures that output as
// the transform hook's writer) and asserts that a log line containing a bearer
// token is (a) written to the on-disk log file and (b) redacted on the way.
func TestFileLoggingThroughRedactionFilter(t *testing.T) {
	require.NoError(t, param.Reset())

	dir := t.TempDir()
	logPath := filepath.Join(dir, "pelican.log")

	t.Cleanup(func() {
		logging.CloseLogger()
		logging.ResetLogFlush()
		ResetGlobalLoggingHooks()
		// Re-establish the censor regex for any later tests in this package.
		globalTransform.regex.Store(regexp.MustCompile(bearerTokenRegexStr))
		log.SetOutput(os.Stderr)
		log.SetLevel(log.InfoLevel)
		_ = param.Reset()
	})

	require.NoError(t, param.Logging_LogLocation.Set(logPath))
	require.NoError(t, param.Logging_Rotation_Frequency.Set("daily"))
	require.NoError(t, param.Logging_Rotation_DisableCompress.Set(true))

	// Start from a clean logging state, then mirror the production sequence.
	logging.ResetLogFlush()
	logging.SetupLogBuffering()

	egrp, egrpCtx := errgroup.WithContext(context.Background())
	logging.SetErrgroup(egrpCtx, egrp)

	// Ensure the censor is active and the configured level admits Info.
	globalTransform.regex.Store(regexp.MustCompile(bearerTokenRegexStr))
	log.SetLevel(log.InfoLevel)

	// 1) Install the async (rotating) file writer as the logrus output.
	logging.FlushLogs(true)
	// 2) Install the redaction/filter hooks, which capture the current output
	//    (the async writer) as the transform hook's sink -- exactly as InitServer
	//    and InitClient do (FlushLogs runs before initFilterLogging).
	initFilterLogging()

	// A bearer token embedded in a URL, like the ones the censor targets.
	signature := strings.Repeat("a", 64)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTUxNjIzOTAyMn0." + signature
	log.Infof("transfer marker-line url=pelican://example.org/data?authz=Bearer%%20%s", token)

	// Drain + flip to synchronous mode so everything is on disk.
	logging.EnterSyncMode()
	require.NoError(t, egrp.Wait())

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	got := string(content)

	assert.Contains(t, got, "marker-line", "the log line should be written to the rotating file")
	assert.Contains(t, got, "REDACTED", "the bearer token should be redacted by the filter hook")
	assert.NotContains(t, got, signature, "the raw token signature must not appear in the log file")
}
