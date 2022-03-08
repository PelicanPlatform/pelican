package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetIps calls main.get_ips with a hostname, checking
// for a valid return value.
func TestGetIps(t *testing.T) {
	t.Parallel()

	ips := get_ips("wlcg-wpad.fnal.gov")
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP.To4() != nil {
			// Make sure that the ip doesn't start with a "[", breaks downloads
			if strings.HasPrefix(ip, "[") {
				t.Fatal("IPv4 address has brackets, will break downloads")
			}
		} else if parsedIP.To16() != nil {
			if !strings.HasPrefix(ip, "[") {
				t.Fatal("IPv6 address doesn't have brackets, downloads will parse it as invalid ports")
			}
		}
	}

}

// TestGetToken tests getToken
func TestGetToken(t *testing.T) {

	// ENVs to test: BEARER_TOKEN, BEARER_TOKEN_FILE, XDG_RUNTIME_DIR/bt_u<uid>, TOKEN, _CONDOR_CREDS/scitoken.use, .condor_creds/scitokens.use
	os.Setenv("BEARER_TOKEN", "bearer_token_contents")
	token, err := getToken()
	assert.NoError(t, err)
	assert.Equal(t, "bearer_token_contents", token)
	os.Unsetenv("BEARER_TOKEN")

	// BEARER_TOKEN_FILE
	tmpDir := t.TempDir()
	token_contents := "bearer_token_file_contents"
	tmpFile := []byte(token_contents)
	bearer_token_file := filepath.Join(tmpDir, "bearer_token_file")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("BEARER_TOKEN_FILE", bearer_token_file)
	token, err = getToken()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("BEARER_TOKEN_FILE")

	// XDG_RUNTIME_DIR/bt_u<uid>
	token_contents = "bearer_token_file_contents xdg"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "bt_u"+strconv.Itoa(os.Getuid()))
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("XDG_RUNTIME_DIR", tmpDir)
	token, err = getToken()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("XDG_RUNTIME_DIR")

	// TOKEN
	token_contents = "bearer_token_file_contents token"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "token_file")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("TOKEN", bearer_token_file)
	token, err = getToken()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("TOKEN")

	// _CONDOR_CREDS/scitokens.use
	token_contents = "bearer_token_file_contents scitokens.use"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "scitokens.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	token, err = getToken()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// Current directory .condor_creds/scitokens.use
	token_contents = "bearer_token_file_contents .condor_creds/scitokens.use"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, ".condor_creds", "scitokens.use")
	err = os.Mkdir(filepath.Join(tmpDir, ".condor_creds"), 0755)
	assert.NoError(t, err)
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	currentDir, err := os.Getwd()
	assert.NoError(t, err)
	err = os.Chdir(tmpDir)
	assert.NoError(t, err)
	token, err = getToken()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	err = os.Chdir(currentDir)
	assert.NoError(t, err)

}

// TestReadMultiTransfer test if we can read multiple transfers from stdin
func TestReadMultiTransfer(t *testing.T) {
	t.Parallel()

	// Test with multiple transfers
	stdin := "[ LocalFileName = \"/path/to/local/copy/of/foo\"; Url = \"url://server/some/directory//foo\" ]\n[ LocalFileName = \"/path/to/local/copy/of/bar\"; Url = \"url://server/some/directory//bar\" ]\n[ LocalFileName = \"/path/to/local/copy/of/qux\"; Url = \"url://server/some/directory//qux\" ]"
	transfers, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
	assert.NoError(t, err)
	assert.Equal(t, 3, len(transfers))
	assert.Equal(t, "/path/to/local/copy/of/foo", transfers[0].destination)
	assert.Equal(t, "url://server/some/directory//foo", transfers[0].source)
	assert.Equal(t, "/path/to/local/copy/of/bar", transfers[1].destination)
	assert.Equal(t, "url://server/some/directory//bar", transfers[1].source)
	assert.Equal(t, "/path/to/local/copy/of/qux", transfers[2].destination)
	assert.Equal(t, "url://server/some/directory//qux", transfers[2].source)

	// Test with single transfers
	stdin = "[ LocalFileName = \"/path/to/local/copy/of/blah\"; Url = \"url://server/some/directory//blah\" ]"
	transfers, err = readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "url://server/some/directory//blah", transfers[0].source)
	assert.Equal(t, "/path/to/local/copy/of/blah", transfers[0].destination)
}
