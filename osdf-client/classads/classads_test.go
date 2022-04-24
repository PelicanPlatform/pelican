package classads

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestStringClassAd(t *testing.T) {
	ad := NewClassAd()
	ad.Set("LocalFileName", "/path/to/local/copy/of/foo")
	adStr := ad.String()
	if adStr != "[LocalFileName = \"/path/to/local/copy/of/foo\"; ]" {
		t.Errorf("ClassAd.String() returned %s, expected \"/path/to/local/copy/of/foo\"", adStr)
	}

	// Load the classad back into a new ClassAd
	ad2, err := ParseClassAd(adStr)
	if err != nil {
		t.Errorf("ParseClassAd() failed: %s", err)
	}
	if ad2.String() != adStr {
		t.Errorf("ParseClassAd() returned %s, expected %s", ad2.String(), adStr)
	}
	localFileName1, err := ad.Get("LocalFileName")
	if err != nil {
		t.Errorf("Get() failed: %s", err)
	}
	localFileName2, err := ad2.Get("LocalFileName")
	if err != nil {
		t.Errorf("Get() failed: %s", err)
	}
	assert.Equal(t, localFileName1, localFileName2)
}

func TestStringQuoteClassAd(t *testing.T) {
	ad := NewClassAd()
	ad.Set("StringValue", "Get quotes \"right\"")
	adStr := ad.String()
	assert.Equal(t, "[StringValue = \"Get quotes \\\"right\\\"\"; ]", adStr)
}

func TestBoolClassAd(t *testing.T) {
	ad := NewClassAd()
	ad.Set("BooleanValue", true)
	adStr := ad.String()
	assert.Equal(t, "[BooleanValue = true; ]", adStr)

	// Load the classad back into a new ClassAd
	ad2, err := ParseClassAd(adStr)
	assert.NoError(t, err, "ParseClassAd() failed")
	assert.Equal(t, adStr, ad2.String())
	boolValue1, err := ad2.Get("BooleanValue")
	assert.NoError(t, err, "Get() failed")
	assert.Equal(t, true, boolValue1.(bool))

}

func TestIntClassAd(t *testing.T) {
	ad := NewClassAd()
	ad.Set("IntValue", 42)
	adStr := ad.String()
	assert.Equal(t, "[IntValue = 42; ]", adStr)

	// Load the classad back into a new ClassAd
	ad2, err := ParseClassAd(adStr)
	assert.NoError(t, err, "ParseClassAd() failed")
	assert.Equal(t, adStr, ad2.String())
	intValue1, err := ad2.Get("IntValue")
	assert.NoError(t, err, "Get() failed")
	assert.Equal(t, 42, intValue1.(int))
}
