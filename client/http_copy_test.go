//go:build !windows

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

package client

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMonitorTPC tests parsing of TPC performance markers
func TestMonitorTPC(t *testing.T) {
	t.Run("SuccessfulTransferWithPerfMarkers", func(t *testing.T) {
		body := strings.NewReader(
			"Perf Marker\n" +
				"Stripe Index: 0\n" +
				"Stripe Bytes Transferred: 1024\n" +
				"Total Stripe Count: 1\n" +
				"End\n" +
				"Perf Marker\n" +
				"Stripe Index: 0\n" +
				"Stripe Bytes Transferred: 2048\n" +
				"Total Stripe Count: 1\n" +
				"End\n" +
				"success: Created\n",
		)

		messages := make(chan tpcStatus, 3)
		err := monitorTPC(context.Background(), messages, body)
		require.NoError(t, err)

		// Should get two progress updates + one done
		msg1 := <-messages
		assert.Equal(t, uint64(1024), msg1.xferred)
		assert.False(t, msg1.done)

		msg2 := <-messages
		assert.Equal(t, uint64(2048), msg2.xferred)
		assert.False(t, msg2.done)

		msg3 := <-messages
		assert.True(t, msg3.done)
		assert.NoError(t, msg3.err)

		// Verify no additional unexpected messages (channel should be closed)
		select {
		case extra, ok := <-messages:
			if ok {
				t.Fatalf("unexpected extra message on channel: %+v", extra)
			}
		default:
		}
	})

	t.Run("FailedTransfer", func(t *testing.T) {
		body := strings.NewReader(
			"failure: Copy failed: no such file\n",
		)

		messages := make(chan tpcStatus, 2)
		err := monitorTPC(context.Background(), messages, body)
		require.NoError(t, err)

		msg := <-messages
		assert.True(t, msg.done)
		assert.Error(t, msg.err)
		assert.Contains(t, msg.err.Error(), "Copy failed")

		// Verify no additional unexpected messages (channel should be closed)
		select {
		case extra, ok := <-messages:
			if ok {
				t.Fatalf("unexpected extra message on channel: %+v", extra)
			}
		default:
		}
	})

	t.Run("MultipleStripes", func(t *testing.T) {
		body := strings.NewReader(
			"Perf Marker\n" +
				"Stripe Index: 0\n" +
				"Stripe Bytes Transferred: 500\n" +
				"Total Stripe Count: 2\n" +
				"End\n" +
				"Perf Marker\n" +
				"Stripe Index: 1\n" +
				"Stripe Bytes Transferred: 700\n" +
				"Total Stripe Count: 2\n" +
				"End\n" +
				"success: Created\n",
		)

		messages := make(chan tpcStatus, 3)
		err := monitorTPC(context.Background(), messages, body)
		require.NoError(t, err)

		msg1 := <-messages
		assert.Equal(t, uint64(500), msg1.xferred)
		assert.False(t, msg1.done)

		msg2 := <-messages
		// Both stripes: 500 + 700 = 1200
		assert.Equal(t, uint64(1200), msg2.xferred)
		assert.False(t, msg2.done)

		msg3 := <-messages
		assert.True(t, msg3.done)
		assert.NoError(t, msg3.err)

		// Verify no additional unexpected messages (channel should be closed)
		select {
		case extra, ok := <-messages:
			if ok {
				t.Fatalf("unexpected extra message on channel: %+v", extra)
			}
		default:
		}
	})

	t.Run("EmptyBody", func(t *testing.T) {
		body := strings.NewReader("")

		messages := make(chan tpcStatus, 1)
		err := monitorTPC(context.Background(), messages, body)
		require.NoError(t, err)

		msg := <-messages
		assert.True(t, msg.done)
		assert.NoError(t, msg.err)
	})
}

// TestSummarizeCopyFailure covers what a destination's refusal looks like by
// the time it reaches the caller.  Before issue #3663 the body was logged and
// then dropped, leaving the user with a bare "TPC COPY failed (HTTP status
// 409)" and no way to learn that the destination they named is a collection.
func TestSummarizeCopyFailure(t *testing.T) {
	t.Run("carries the destination's reason", func(t *testing.T) {
		body := []byte("failure: Unable to create /ospool/ap40/data/user/tpc2; is a directory, " +
			"local=/ospool/ap40/data/user/tpc2, remote=https://dtn.example:8443/ospool/ap40/data/user/tpc1/file")
		got := summarizeCopyFailure(body)
		assert.Contains(t, got, "is a directory")
		assert.False(t, strings.HasPrefix(got, "failure:"),
			"XRootD's \"failure:\" prefix adds nothing to a message that already says the copy failed")
	})

	t.Run("flattens a multi-line body to one line", func(t *testing.T) {
		got := summarizeCopyFailure([]byte("  first line\n\tsecond line\n\n"))
		assert.Equal(t, "first line second line", got)
	})

	t.Run("bounds a hostile body", func(t *testing.T) {
		got := summarizeCopyFailure([]byte(strings.Repeat("A", 4096)))
		assert.Less(t, len(got), 4096, "a remote peer must not choose how long the error message is")
	})

	t.Run("says nothing when the body is empty", func(t *testing.T) {
		assert.Empty(t, summarizeCopyFailure(nil))
		assert.Empty(t, summarizeCopyFailure([]byte("   \n ")))
	})
}
