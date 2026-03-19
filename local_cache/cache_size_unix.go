//go:build !windows

package local_cache

import (
	"syscall"

	"github.com/alecthomas/units"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
)

// getCacheSize determines the maximum cache size for a directory.
//
// If LocalCache.Size is configured, that explicit value is used.
// Otherwise the size is auto-detected from the filesystem.  When
// auto-detecting, the result is Bavail (free space) plus this
// directory's tracked usage from the database, so that the cache's
// existing data does not artificially shrink the limit.
func getCacheSize(cacheDir string, db *CacheDB, storageID StorageID) (cacheSize uint64, err error) {
	sizeStr := param.LocalCache_Size.GetString()
	if sizeStr == "" || sizeStr == "0" {
		var stat syscall.Statfs_t
		if err = syscall.Statfs(cacheDir, &stat); err != nil {
			err = errors.Wrapf(err, "unable to determine free space for cache directory %s", cacheDir)
			return
		}
		cacheSize = stat.Bavail * uint64(stat.Bsize)

		// Add back this directory's tracked usage so that existing
		// cached data doesn't shrink the effective limit.  Without
		// this, Bavail decreases as the cache fills, creating a
		// feedback loop that triggers premature eviction.
		if db != nil {
			if nsUsage, usageErr := db.GetDirUsage(storageID); usageErr == nil {
				for _, bytes := range nsUsage {
					if bytes > 0 {
						cacheSize += uint64(bytes)
					}
				}
			}
		}
	} else {
		var signedCacheSize int64
		signedCacheSize, err = units.ParseStrictBytes(param.LocalCache_Size.GetString())
		if err != nil {
			return
		}
		cacheSize = uint64(signedCacheSize)
	}
	return
}
