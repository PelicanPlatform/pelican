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
package local_cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFinishedDownloadIsNotInProgress checks what eviction counts as a
// download in progress.  A download's entry in activeDownloads is removed
// by a goroutine only after the download has finished, so an eviction just
// after a download used to find the entry and refuse, or skip, an object
// that was already complete.
func TestFinishedDownloadIsNotInProgress(t *testing.T) {
	pc := &PersistentCache{activeDownloads: make(map[ObjectHash]*persistentDownload)}
	const hash = ObjectHash("object")
	assert.False(t, pc.downloadInProgress(hash), "no download")

	dl := &persistentDownload{completionDone: make(chan struct{})}
	pc.activeDownloads[hash] = dl
	assert.True(t, pc.downloadInProgress(hash), "a download that has not finished")

	close(dl.completionDone)
	assert.False(t, pc.downloadInProgress(hash), "a finished download whose entry is not yet removed")
}
