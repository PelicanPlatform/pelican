package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestInitServerRoot(t *testing.T) {
	err := InitServer()
	if err != nil {
		t.Fatal(err)
	}

	//Do a few tests of filenames to make sure everything looks good
	assert.Equal(t, "/etc/pelican/certificates/tls.crt", TLSCertificate.GetPath())
	assert.Equal(t, "/var/cache/pelican/maxmind/GeoLite2-City.mmdb", viper.GetString("GeoIPLocation"))
}

func TestInitServerNonRoot(t *testing.T) {
	isRootExec = false
	err := InitServer()
	if err != nil {
		t.Fatal(err)
	}

	//Do a few tests of filenames to make sure everything looks good
	assert.Equal(t, "/root/.config/pelican/robots.txt", RobotsTxtFile.GetPath())
	assert.Equal(t, "/root/.config/pelican/ns-registry.sqlite", viper.GetString("NSRegistryLocation"))
	xString := XrootdRun.GetPath()
	lastIndex := strings.LastIndex(xString, "-")
	assert.Equal(t, "/tmp/pelican-xrootd", xString[:lastIndex])
}
