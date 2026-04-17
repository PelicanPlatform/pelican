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

		messages := make(chan tpcStatus, 10)
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

		messages := make(chan tpcStatus, 10)
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

		messages := make(chan tpcStatus, 10)
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

		messages := make(chan tpcStatus, 10)
		err := monitorTPC(context.Background(), messages, body)
		require.NoError(t, err)

		msg := <-messages
		assert.True(t, msg.done)
		assert.NoError(t, msg.err)
	})
}
