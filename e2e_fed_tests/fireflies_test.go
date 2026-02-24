//go:build !windows && !darwin

package fed_tests

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestFireflies(t *testing.T) {

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	originConfig := `
Origin:
  StorageType: posix
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Reads", "Writes", "Listings"]
Xrootd:
  EnableFireflies: true
  FirefliesForwardingAddress: "127.0.0.1:10514"
`
	// Launch udp listener on port 10514
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 10514})
	require.NoError(t, err)
	defer udpListener.Close()

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	var bytesRead atomic.Int64
	go func() {
		buf := make([]byte, 4*1024)
		for {
			select {
			case <-ft.Ctx.Done():
				return
			default:
			}
			_ = udpListener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := udpListener.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			bytesRead.Add(int64(n))
			t.Logf("Received content: \n%s", string(buf[:n]))
		}
	}()

	// upload a file to the origin
	uploadFile := t.TempDir() + "/test_file.txt"
	content := "Hello, world!"
	require.NoError(t, os.WriteFile(uploadFile, []byte(content), 0644))
	uploadURL := fmt.Sprintf("pelican://%s:%d/test/test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	_, err = client.DoPut(ft.Ctx, uploadFile, uploadURL, false, client.WithToken(ft.Token))
	require.NoError(t, err)

	// download the file from the origin
	downloadFile := t.TempDir() + "/downloaded_file.txt"
	_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)

	// verify the content of the downloaded file
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, content, string(downloadedContent))

	assert.Eventually(t, func() bool {
		return bytesRead.Load() > 0
	}, 10*time.Second, 100*time.Millisecond, "Expected data to be forwarded to the udp listener")
}
