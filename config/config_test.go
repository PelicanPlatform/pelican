package config

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestInitServer(t *testing.T) {
	err := InitServer()
	if err != nil {
		t.Fatal(err)
	}

	if IsRootExecution() {
		//Do a few tests of filenames to make sure everything looks good
		assert.Equal(t, "/etc/pelican/certificates/tls.crt", TLSCertificate.GetPath())
		assert.Equal(t, "/var/cache/pelican/maxmind/GeoLite2-City.mmdb", viper.GetString("GeoIPLocation"))
	} else {
		assert.Equal(t, filepath.Join(configBase, "robots.txt"), RobotsTxtFile.GetPath())
		assert.Equal(t, filepath.Join(configBase, "ns-registry.sqlite"), viper.GetString("NSRegistryLocation"))
	}
}
