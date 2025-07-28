package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestUpdateXrootdCacheEvictionMetrics(t *testing.T) {
	// Reset metrics to ensure a clean slate for testing
	XrootdCacheEvictionDirNumIos.Reset()
	XrootdCacheEvictionDirDuration.Reset()
	XrootdCacheEvictionDirBytes.Reset()
	XrootdCacheEvictionDirStBlockBytes.Reset()
	XrootdCacheEvictionDirNCksumErrors.Reset()
	XrootdCacheEvictionDirFiles.Reset()
	XrootdCacheEvictionDirDirectories.Reset()
	XrootdCacheEvictionDirLastAccessTime.Reset()
	XrootdCacheEvictionDirStBlocksUsage.Reset()
	XrootdCacheEvictionDirNFilesOpen.Reset()
	XrootdCacheEvictionDirNFiles.Reset()
	XrootdCacheEvictionDirNDirectories.Reset()

	dirStatistics := DirStatistics{
		DirStates: []DirState{
			{
				DirName: "", // Root directory
				Stats: DirStats{
					NumIos:              10,
					Duration:            100,
					BytesHit:            1000,
					BytesMissed:         200,
					BytesBypassed:       50,
					BytesWritten:        500,
					StBlocksAdded:       10,
					NCksumErrors:        1,
					StBlocksRemoved:     2,
					NFilesOpened:        5,
					NFilesClosed:        4,
					NFilesCreated:       3,
					NFilesRemoved:       2,
					NDirectoriesCreated: 1,
					NDirectoriesRemoved: 0,
				},
				Usage: Usage{
					LastOpenTime:  1678886400,
					LastCloseTime: 1678886401,
					StBlocks:      8,
					NFilesOpen:    1,
					NFiles:        5,
					NDirectories:  1,
				},
				Parent: -1,
			},
			{
				DirName: "subdir",
				Stats: DirStats{
					NumIos:              20,
					Duration:            200,
					BytesHit:            2000,
					BytesMissed:         400,
					BytesBypassed:       100,
					BytesWritten:        1000,
					StBlocksAdded:       20,
					NCksumErrors:        2,
					StBlocksRemoved:     4,
					NFilesOpened:        10,
					NFilesClosed:        8,
					NFilesCreated:       6,
					NFilesRemoved:       4,
					NDirectoriesCreated: 2,
					NDirectoriesRemoved: 1,
				},
				Usage: Usage{
					LastOpenTime:  1678886402,
					LastCloseTime: 1678886403,
					StBlocks:      16,
					NFilesOpen:    2,
					NFiles:        10,
					NDirectories:  2,
				},
				Parent: 0,
			},
		},
	}

	updateXrootdCacheEvictionMetrics(dirStatistics)

	// Assertions for root directory ("/")
	assert.Equal(t, float64(10), testutil.ToFloat64(XrootdCacheEvictionDirNumIos.WithLabelValues("/")), "NumIos for /")
	assert.Equal(t, float64(100), testutil.ToFloat64(XrootdCacheEvictionDirDuration.WithLabelValues("/")), "Duration for /")
	assert.Equal(t, float64(1000), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/", "hit")), "BytesHit for /")
	assert.Equal(t, float64(200), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/", "missed")), "BytesMissed for /")
	assert.Equal(t, float64(50), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/", "bypassed")), "BytesBypassed for /")
	assert.Equal(t, float64(500), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/", "written")), "BytesWritten for /")
	assert.Equal(t, float64(10*512), testutil.ToFloat64(XrootdCacheEvictionDirStBlockBytes.WithLabelValues("/", "added")), "StBlocksAdded for /")
	assert.Equal(t, float64(2*512), testutil.ToFloat64(XrootdCacheEvictionDirStBlockBytes.WithLabelValues("/", "removed")), "StBlocksRemoved for /")
	assert.Equal(t, float64(1), testutil.ToFloat64(XrootdCacheEvictionDirNCksumErrors.WithLabelValues("/")), "NCksumErrors for /")
	assert.Equal(t, float64(5), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/", "opened")), "NFilesOpened for /")
	assert.Equal(t, float64(4), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/", "closed")), "NFilesClosed for /")
	assert.Equal(t, float64(3), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/", "created")), "NFilesCreated for /")
	assert.Equal(t, float64(2), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/", "removed")), "NFilesRemoved for /")
	assert.Equal(t, float64(1), testutil.ToFloat64(XrootdCacheEvictionDirDirectories.WithLabelValues("/", "created")), "NDirectoriesCreated for /")
	assert.Equal(t, float64(0), testutil.ToFloat64(XrootdCacheEvictionDirDirectories.WithLabelValues("/", "removed")), "NDirectoriesRemoved for /")

	assert.Equal(t, float64(1678886400), testutil.ToFloat64(XrootdCacheEvictionDirLastAccessTime.WithLabelValues("/", "open")), "LastOpenTime for /")
	assert.Equal(t, float64(1678886401), testutil.ToFloat64(XrootdCacheEvictionDirLastAccessTime.WithLabelValues("/", "close")), "LastCloseTime for /")
	assert.Equal(t, float64(8), testutil.ToFloat64(XrootdCacheEvictionDirStBlocksUsage.WithLabelValues("/")), "StBlocks for /")
	assert.Equal(t, float64(1), testutil.ToFloat64(XrootdCacheEvictionDirNFilesOpen.WithLabelValues("/")), "NFilesOpen for /")
	assert.Equal(t, float64(5), testutil.ToFloat64(XrootdCacheEvictionDirNFiles.WithLabelValues("/")), "NFiles for /")
	assert.Equal(t, float64(1), testutil.ToFloat64(XrootdCacheEvictionDirNDirectories.WithLabelValues("/")), "NDirectories for /")

	// Assertions for subdirectory ("/subdir")
	assert.Equal(t, float64(20), testutil.ToFloat64(XrootdCacheEvictionDirNumIos.WithLabelValues("/subdir")), "NumIos for /subdir")
	assert.Equal(t, float64(200), testutil.ToFloat64(XrootdCacheEvictionDirDuration.WithLabelValues("/subdir")), "Duration for /subdir")
	assert.Equal(t, float64(2000), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/subdir", "hit")), "BytesHit for /subdir")
	assert.Equal(t, float64(400), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/subdir", "missed")), "BytesMissed for /subdir")
	assert.Equal(t, float64(100), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/subdir", "bypassed")), "BytesBypassed for /subdir")
	assert.Equal(t, float64(1000), testutil.ToFloat64(XrootdCacheEvictionDirBytes.WithLabelValues("/subdir", "written")), "BytesWritten for /subdir")
	assert.Equal(t, float64(20*512), testutil.ToFloat64(XrootdCacheEvictionDirStBlockBytes.WithLabelValues("/subdir", "added")), "StBlocksAdded for /subdir")
	assert.Equal(t, float64(4*512), testutil.ToFloat64(XrootdCacheEvictionDirStBlockBytes.WithLabelValues("/subdir", "removed")), "StBlocksRemoved for /subdir")
	assert.Equal(t, float64(2), testutil.ToFloat64(XrootdCacheEvictionDirNCksumErrors.WithLabelValues("/subdir")), "NCksumErrors for /subdir")
	assert.Equal(t, float64(10), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/subdir", "opened")), "NFilesOpened for /subdir")
	assert.Equal(t, float64(8), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/subdir", "closed")), "NFilesClosed for /subdir")
	assert.Equal(t, float64(6), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/subdir", "created")), "NFilesCreated for /subdir")
	assert.Equal(t, float64(4), testutil.ToFloat64(XrootdCacheEvictionDirFiles.WithLabelValues("/subdir", "removed")), "NFilesRemoved for /subdir")
	assert.Equal(t, float64(2), testutil.ToFloat64(XrootdCacheEvictionDirDirectories.WithLabelValues("/subdir", "created")), "NDirectoriesCreated for /subdir")
	assert.Equal(t, float64(1), testutil.ToFloat64(XrootdCacheEvictionDirDirectories.WithLabelValues("/subdir", "removed")), "NDirectoriesRemoved for /subdir")

	assert.Equal(t, float64(1678886402), testutil.ToFloat64(XrootdCacheEvictionDirLastAccessTime.WithLabelValues("/subdir", "open")), "LastOpenTime for /subdir")
	assert.Equal(t, float64(1678886403), testutil.ToFloat64(XrootdCacheEvictionDirLastAccessTime.WithLabelValues("/subdir", "close")), "LastCloseTime for /subdir")
	assert.Equal(t, float64(16), testutil.ToFloat64(XrootdCacheEvictionDirStBlocksUsage.WithLabelValues("/subdir")), "StBlocks for /subdir")
	assert.Equal(t, float64(2), testutil.ToFloat64(XrootdCacheEvictionDirNFilesOpen.WithLabelValues("/subdir")), "NFilesOpen for /subdir")
	assert.Equal(t, float64(10), testutil.ToFloat64(XrootdCacheEvictionDirNFiles.WithLabelValues("/subdir")), "NFiles for /subdir")
	assert.Equal(t, float64(2), testutil.ToFloat64(XrootdCacheEvictionDirNDirectories.WithLabelValues("/subdir")), "NDirectories for /subdir")
}

func TestUpdateXrootdCacheEvictionMetrics_PathReconstruction(t *testing.T) {
	// Reset metrics to ensure a clean slate for testing
	XrootdCacheEvictionDirNumIos.Reset()

	dirStatistics := DirStatistics{
		DirStates: []DirState{
			{
				DirName: "", // Root directory
				Stats:   DirStats{NumIos: 1},
				Parent:  -1,
			},
			{
				DirName: "foo",
				Stats:   DirStats{NumIos: 2},
				Parent:  0,
			},
			{
				DirName: "bar",
				Stats:   DirStats{NumIos: 3},
				Parent:  1,
			},
		},
	}

	updateXrootdCacheEvictionMetrics(dirStatistics)

	assert.Equal(t, float64(1), testutil.ToFloat64(XrootdCacheEvictionDirNumIos.WithLabelValues("/")))
	assert.Equal(t, float64(2), testutil.ToFloat64(XrootdCacheEvictionDirNumIos.WithLabelValues("/foo")))
	assert.Equal(t, float64(3), testutil.ToFloat64(XrootdCacheEvictionDirNumIos.WithLabelValues("/foo/bar")))
}
