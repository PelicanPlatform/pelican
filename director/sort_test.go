package director

import (
	"bytes"
	"net"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestCheckOverrides(t *testing.T) {
	viper.Reset()

	// We'll also check that our logging feature responsibly reports
	// what Pelican is telling the user.
	logOutput := &(bytes.Buffer{})
	log.SetOutput(logOutput)
	log.SetLevel(log.DebugLevel)

	// Mockup of the YAML we need to kick off the tests. Note that if you mess with it, you need to
	// make sure the indentations are spaces.
	yamlMockup := `
GeoIPOverrides:
  # Valid IPv4
  - IP: "192.168.0.1"
    Coordinate:
      Lat: 123.4
      Long: 987.6
  # Valid IPv4 CIDR
  - IP: "10.0.0.0/24"
    Coordinate:
      Lat: 43.073904
      Long: -89.384859
  # Malformed IPv4
  - IP: "192.168.0"
    Coordinate:
      Lat: 1000.0
      Long: 2000.0
  # Malformed IPv4 CIDR
  - IP: "10.0.0./24"
    Coordinate:
      Lat: 1000.0
      Long: 2000.0
  # Valid IPv6
  - IP: "FC00:0000:0000:0000:0000:0000:0000:0001"
    Coordinate:
      Lat: 123.4
      Long: 987.6
  # Valid IPv6
  - IP: "FD00::FAB2/112"
    Coordinate:
      Lat: 43.073904
      Long: -89.384859
  # Malformed IPv6
  - IP: "FD00::000G"
    Coordinate:
      Lat: 1000.0
      Long: 2000.0
  # Malformed IPv6
  - IP: "FD00::000F/11S"
    Coordinate:
      Lat: 1000.0
      Long: 2000.0
`

	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(yamlMockup))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	t.Run("test-no-ipv4-match", func(t *testing.T) {
		// In the event that no override is detected, `checkOverrides` should return a nil override
		addr := net.ParseIP("192.168.0.2")
		coordinate := checkOverrides(addr)
		require.Nil(t, coordinate)
	})

	t.Run("test-no-ipv6-match", func(t *testing.T) {
		addr := net.ParseIP("ABCD::0123")
		coordinate := checkOverrides(addr)
		require.Nil(t, coordinate)
	})

	t.Run("test-log-output", func(t *testing.T) {
		// Check that the log caught our malformed IP and CIDR. We only need to test this once, because it is only logged the very first time.
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride address (192.168.0). Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride CIDR address (10.0.0./24): invalid CIDR address: 10.0.0./24."+
			" Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride address (FD00::000G). Unable to use for GeoIP resolution!")
		require.Contains(t, logOutput.String(), "Failed to parse configured GeoIPOverride CIDR address (FD00::000F/11S): invalid CIDR address: FD00::000F/11S."+
			" Unable to use for GeoIP resolution!")
	})

	t.Run("test-ipv4-match", func(t *testing.T) {
		// When we match against a regular IPv4, we expect a non-nil coordinate
		expectedCoordinate := Coordinate{
			Lat:  123.4,
			Long: 987.6,
		}

		addr := net.ParseIP("192.168.0.1")
		coordinate := checkOverrides(addr)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})

	t.Run("test-ipv4-CIDR-match", func(t *testing.T) {
		// Same goes for CIDR matches
		expectedCoordinate := Coordinate{
			Lat:  43.073904,
			Long: -89.384859,
		}

		addr := net.ParseIP("10.0.0.136")
		coordinate := checkOverrides(addr)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})

	t.Run("test-ipv6-match", func(t *testing.T) {
		expectedCoordinate := Coordinate{
			Lat:  123.4,
			Long: 987.6,
		}

		addr := net.ParseIP("FC00::0001")
		coordinate := checkOverrides(addr)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})

	t.Run("test-ipv6-CIDR-match", func(t *testing.T) {
		expectedCoordinate := Coordinate{
			Lat:  43.073904,
			Long: -89.384859,
		}

		addr := net.ParseIP("FD00::FA1B")
		coordinate := checkOverrides(addr)
		require.Equal(t, expectedCoordinate.Lat, coordinate.Lat)
		require.Equal(t, expectedCoordinate.Long, coordinate.Long)
	})

	viper.Reset()
}
