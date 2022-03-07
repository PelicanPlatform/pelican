package classads

import (
	"strings"
	"testing"
)

func TestReadClassAd(t *testing.T) {
	var err error
	reader := strings.NewReader("[ LocalFileName = \"/path/to/local/copy/of/foo\"; Url = \"url://server/some/directory//foo\" ]\n[ LocalFileName = \"/path/to/local/copy/of/bar\"; Url = \"url://server/some/directory//bar\" ]\n[ LocalFileName = \"/path/to/local/copy/of/qux\"; Url = \"url://server/some/directory//qux\" ]")

	ads, err := ReadClassAd(reader)
	if err != nil {
		t.Errorf("ReadClassAd() failed: %s", err)
	}
	if len(ads) != 3 {
		t.Errorf("ReadClassAd() returned %d ads, expected 3", len(ads))
	}

	strInterface, err := ads[0].Get("LocalFileName")
	if err != nil {
		t.Errorf("GetStringValue() failed: %s", err)
	}
	if strInterface.(string) != "/path/to/local/copy/of/foo" {
		t.Errorf("GetStringValue() returned %s, expected \"/path/to/local/copy/of/foo\"", strInterface.(string))
	}
}
