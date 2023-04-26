package stashcp

import (
	"net"
	"net/url"
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

	// Need a namespace for token acquisition
	namespace, err := MatchNamespace("/user/foo")
	assert.NoError(t, err)

	url, err := url.Parse("osdf:///user/foo")
	assert.NoError(t, err)

	// ENVs to test: BEARER_TOKEN, BEARER_TOKEN_FILE, XDG_RUNTIME_DIR/bt_u<uid>, TOKEN, _CONDOR_CREDS/scitoken.use, .condor_creds/scitokens.use
	os.Setenv("BEARER_TOKEN", "bearer_token_contents")
	token, err := getToken(url, namespace, true, "")
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
	token, err = getToken(url, namespace, true, "")
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
	token, err = getToken(url, namespace, true, "")
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
	token, err = getToken(url, namespace, true, "")
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
	token, err = getToken(url, namespace, true, "")
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.use
	token_contents = "bearer_token_file_contents renamed.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	renamedUrl, err := url.Parse("renamed+osdf:///user/ligo/frames")
	assert.NoError(t, err)
	renamedNamespace, err := MatchNamespace("/user/ligo/frames")
	assert.NoError(t, err)
	token, err = getToken(renamedUrl, renamedNamespace, false, "")
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.use
	token_contents = "bearer_token_file_contents renamed.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	renamedUrl, err = url.Parse("/user/ligo/frames")
	assert.NoError(t, err)
	renamedNamespace, err = MatchNamespace("/user/ligo/frames")
	assert.NoError(t, err)
	token, err = getToken(renamedUrl, renamedNamespace, false, "renamed")
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
	token, err = getToken(url, namespace, true, "")
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	err = os.Chdir(currentDir)
	assert.NoError(t, err)

}

// TestGetTokenName tests getTokenName
func TestGetTokenName(t *testing.T) {
	cases := []struct {
		url    string
		name   string
		scheme string
	}{
		{"osdf://blah+asdf", "", "osdf"},
		{"stash://blah+asdf", "", "stash"},
		{"file://blah+asdf", "", "file"},
		{"tokename+osdf://blah+asdf", "tokename", "osdf"},
		{"tokename+stash://blah+asdf", "tokename", "stash"},
		{"tokename+file://blah+asdf", "tokename", "file"},
		{"tokename+tokename2+osdf://blah+asdf", "tokename+tokename2", "osdf"},
		{"token+tokename2+stash://blah+asdf", "token+tokename2", "stash"},
		{"token.use+stash://blah+asdf", "token.use", "stash"},
		{"token.blah.asdf+stash://blah+asdf", "token.blah.asdf", "stash"},
	}
	for _, c := range cases {
		url, err := url.Parse(c.url)
		assert.NoError(t, err)
		scheme, tokenName := getTokenName(url)
		assert.Equal(t, c.name, tokenName)
		assert.Equal(t, c.scheme, scheme)
	}

}

func FuzzGetTokenName(f *testing.F) {
	testcases := []string{"", "tokename", "tokename+tokename2"}
	for _, tc := range testcases {
		f.Add(tc) // Use f.Add to provide a seed corpus
	}
	f.Fuzz(func(t *testing.T, orig string) {
		// Make sure it's a valid URL
		urlString := orig + "+osdf://blah+asdf"
		url, err := url.Parse(urlString)
		// If it's not a valid URL, then it's not a valid token name
		if err != nil || url.Scheme == "" {
			return
		}
		assert.NoError(t, err)
		_, tokenName := getTokenName(url)
		assert.Equal(t, strings.ToLower(orig), tokenName, "URL: "+urlString+"URL String: "+url.String()+" Scheme: "+url.Scheme)
	})
}

func TestParseJobAd(t *testing.T) {
	// Job ad file does not exist
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, ".job.ad")
	os.Setenv("_CONDOR_JOB_AD", path)

	payload := payloadStruct{}
	parse_job_ad(payload)
}