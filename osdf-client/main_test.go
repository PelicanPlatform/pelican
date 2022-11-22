package stashcp

import (
	"github.com/stretchr/testify/assert"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
	token, err := getToken("")
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
	token, err = getToken("")
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
	token, err = getToken("")
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
	token, err = getToken("")
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
	token, err = getToken("")
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
	token, err = getToken("")
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	err = os.Chdir(currentDir)
	assert.NoError(t, err)

}

// TestGetTokenName tests getTokenName
func TestGetTokenName(t *testing.T) {
	cases := []struct {
		url  string
		name string
	}{
		{"osdf://blah+asdf", ""},
		{"stash://blah+asdf", ""},
		{"file://blah+asdf", ""},
		{"osdf+tokename://blah+asdf", "tokename"},
		{"stash+tokename://blah+asdf", "tokename"},
		{"file+tokename://blah+asdf", "tokename"},
		{"osdf+tokename+tokename2://blah+asdf", "tokename+tokename2"},
		{"stash+token+tokename2://blah+asdf", "token+tokename2"},
		{"stash+token.use://blah+asdf", "token.use"},
		{"stash+token.blah.asdf://blah+asdf", "token.blah.asdf"},
	}
	for _, c := range cases {
		url, err := url.Parse(c.url)
		assert.NoError(t, err)
		assert.Equal(t, c.name, getTokenName(url))
	}

}

func FuzzGetTokenName(f *testing.F) {
	testcases := []string{"", "tokename", "tokename+tokename2"}
	for _, tc := range testcases {
		f.Add(tc) // Use f.Add to provide a seed corpus
	}
	f.Fuzz(func(t *testing.T, orig string) {
		// Make sure it's a valid URL
		urlString := "osdf+" + orig + "://blah+asdf"
		url, err := url.Parse(urlString)
		// If it's not a valid URL, then it's not a valid token name
		if err != nil || url.Scheme == "" {
			return
		}
		assert.NoError(t, err)
		assert.Equal(t, strings.ToLower(orig), getTokenName(url), "URL: "+urlString+"URL String: "+url.String()+" Scheme: "+url.Scheme)
	})
}
