//go:build windows

package local_cache

import (
	"github.com/alecthomas/units"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
)

func getCacheSize(string) (cacheSize uint64, err error) {
	sizeStr := param.LocalCache_Size.GetString()
	if sizeStr == "" || sizeStr == "0" {
		log.Warningln("Cache size is unset and Pelican is unable to determine filesystem size; using 10GB as the default")
		sizeStr = "10GB"
	}
	if signedCacheSize, err := units.ParseStrictBytes(param.LocalCache_Size.GetString()); err == nil {
		cacheSize = uint64(signedCacheSize)
	}
	return
}
