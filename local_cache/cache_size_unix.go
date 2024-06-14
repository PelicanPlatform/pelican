//go:build !windows

package local_cache

import (
	"syscall"

	"github.com/alecthomas/units"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
)

func getCacheSize(cacheDir string) (cacheSize uint64, err error) {
	sizeStr := param.LocalCache_Size.GetString()
	if sizeStr == "" || sizeStr == "0" {
		var stat syscall.Statfs_t
		if err = syscall.Statfs(cacheDir, &stat); err != nil {
			err = errors.Wrapf(err, "unable to determine free space for cache directory %s", cacheDir)
			return
		}
		cacheSize = stat.Bavail * uint64(stat.Bsize)
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
