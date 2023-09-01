/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package classads

import (
	"bufio"
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

func TestOddClassads(t *testing.T) {
	// Test input with malformed URL (using semi-colon instead of comma)
	input := `[ LocalFileName = "/var/lib/condor/execute/dir_22284/glide_9GSlr9/execute/dir_69758/file2"; Url = "stash:///osgconnect/public/$USER/file1; stash:///osgconnect/public/$USER/file2" ]`
	ads, err := ReadClassAd(strings.NewReader(input))
	assert.NoError(t, err, "ReafddClassAd() failed")
	assert.Equal(t, 1, len(ads), "ReadClassAd() returned %d ads, expected 1", len(ads))
	localFileName, err := ads[0].Get("LocalFileName")
	assert.NoError(t, err, "Get(LocalFileName) failed")
	assert.Equal(t, "/var/lib/condor/execute/dir_22284/glide_9GSlr9/execute/dir_69758/file2", localFileName.(string))
	url, err := ads[0].Get("Url")
	assert.NoError(t, err, "Get(Url) failed")
	assert.Equal(t, "stash:///osgconnect/public/$USER/file1; stash:///osgconnect/public/$USER/file2", url.(string))

	// Test input with a "[" in the value
	input = `[ LocalFileName = "/var/lib/condor/execute/dir_22284/glide_9GSlr9/execute/dir_69758/file2"; Url = "stash:///osgconnect/public/$USER/file1[1]; stash:///osgconnect/public/$USER/file2" ]`
	ads, err = ReadClassAd(strings.NewReader(input))
	assert.NoError(t, err, "ReadClassAd() failed")
	assert.Equal(t, 1, len(ads), "ReadClassAd() returned %d ads, expected 1", len(ads))
	localFileName, err = ads[0].Get("LocalFileName")
	assert.NoError(t, err, "Get(LocalFileName) failed")
	assert.Equal(t, "/var/lib/condor/execute/dir_22284/glide_9GSlr9/execute/dir_69758/file2", localFileName.(string))
	url, err = ads[0].Get("Url")
	assert.NoError(t, err, "Get(Url) failed")
	assert.Equal(t, "stash:///osgconnect/public/$USER/file1[1]; stash:///osgconnect/public/$USER/file2", url.(string))

}

func TestAttributeSplitFunc(t *testing.T) {
	input := `LocalFileName = "/var/lib/condor/execute/dir_22284/glide_9GSlr9/execute/dir_69758/file2"; Url = "stash:///osgconnect/public/$USER/file1; stash:///osgconnect/public/$USER/file2"`

	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(attributeSplitFunc)
	attributes := make([]string, 0)
	for scanner.Scan() {
		attributes = append(attributes, scanner.Text())
	}
	assert.Equal(t, nil, scanner.Err(), "attributeSplitFunc() failed: %s", scanner.Err())
	assert.Equal(t, 2, len(attributes), "attributeSplitFunc() returned %d attributes, expected 2", len(attributes))
	assert.Equal(t, `LocalFileName = "/var/lib/condor/execute/dir_22284/glide_9GSlr9/execute/dir_69758/file2"`, attributes[0])
	assert.Equal(t, `Url = "stash:///osgconnect/public/$USER/file1; stash:///osgconnect/public/$USER/file2"`, attributes[1])

}
