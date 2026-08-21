//go:build windows

package local_cache

import (
	"github.com/alecthomas/units"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

func getCacheSize(_ string, _ *CacheDB, _ StorageID) (cacheSize uint64, err error) {
	sizeStr := param.LocalCache_Size.GetString()
	if sizeStr == "" || sizeStr == "0" {
		log.Warningln("Cache size is unset and Pelican is unable to determine filesystem size; using 10GB as the default")
		sizeStr = "10GB"
	}
	var signedCacheSize int64
	signedCacheSize, err = units.ParseStrictBytes(sizeStr)
	if err != nil {
		return
	}
	cacheSize = uint64(signedCacheSize)
	return
}
