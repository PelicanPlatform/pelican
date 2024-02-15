/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type ClassAd struct {
	attributes map[string]interface{}
}

func NewClassAd() *ClassAd {
	return &ClassAd{
		attributes: make(map[string]interface{}),
	}
}

// Get returns the value of the attribute with the given name.
func (c *ClassAd) Get(name string) (interface{}, error) {
	if c.attributes == nil {
		return nil, nil
	} else if value, ok := c.attributes[name]; ok {
		return value, nil
	} else {
		return nil, nil
	}
}

func (c *ClassAd) Set(name string, value interface{}) {
	// Escape any quotes in the string
	c.attributes[name] = value
}

func (c *ClassAd) String() string {
	var buffer bytes.Buffer
	buffer.WriteString("[")
	for name, value := range c.attributes {
		buffer.WriteString(name)
		buffer.WriteString(" = ")
		switch v := value.(type) {
		case string:
			buffer.WriteString(strconv.QuoteToASCII(v))
		case map[string]interface{}:
			buffer.WriteString("[")
			for key, value := range v {
				buffer.WriteString(key)
				buffer.WriteString(" = ")
				switch valueType := value.(type) {
				case int, int64:
					fmt.Fprintf(&buffer, "%v; ", valueType)
				case string:
					fmt.Fprintf(&buffer, "%s; ", strconv.QuoteToASCII(valueType))
				case bool:
					fmt.Fprintf(&buffer, "%t; ", valueType)
				case float64:
					fmt.Fprintf(&buffer, "%.3f; ", valueType)
				case time.Duration:
					// convert to seconds rounded to nearest millisecond, get 3 significant figures
					valueTypeFloat := float64(valueType.Round(time.Millisecond).Milliseconds()) / 1000.0
					fmt.Fprintf(&buffer, "%.3f; ", valueTypeFloat)
				default:
					if str, ok := valueType.(string); ok {
						fmt.Fprintf(&buffer, "%s; ", strconv.QuoteToASCII(str))
					} else {
						fmt.Fprintf(&buffer, "%v; ", valueType)
					}
				}
			}
			buffer.WriteString("]")
		default:
			buffer.WriteString(fmt.Sprintf("%v", value))
		}
		buffer.WriteString("; ")
	}
	buffer.WriteString("]")
	return buffer.String()
}

// ReadClassAd reads a ClassAd from the given reader.
func ReadClassAd(reader io.Reader) (ads []ClassAd, err error) {

	// Catch any panics and return an error instead
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("error reading classad: %v", r)
		}
	}()

	scanner := bufio.NewScanner(reader)
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}

		// Watch out for brackets inside quotes
		insideQuotes := false
		for i, curChar := range data {
			if curChar == '"' && !(i > 0 && data[i-1] == '\\') {
				insideQuotes = !insideQuotes
			} else if curChar == ']' && !insideQuotes {
				return i + 1, data[0 : i+1], nil
			}
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}
	scanner.Split(split)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Parse the classad
		ad, err := ParseClassAd(line)
		if err != nil {
			return nil, err
		}
		ads = append(ads, ad)

	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return ads, nil
}

func ParseClassAd(line string) (ClassAd, error) {
	var ad ClassAd
	ad.attributes = make(map[string]interface{})

	// Trim the spaces and "[" "]"
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "[")
	line = strings.TrimSuffix(line, "]")

	attributeScanner := bufio.NewScanner(strings.NewReader(line))
	attributeScanner.Split(attributeSplitFunc)
	for attributeScanner.Scan() {
		attrStr := attributeScanner.Text()
		attrStr = strings.TrimSpace(attrStr)
		if attrStr == "" {
			continue
		}

		// Split on the first "="
		attrSplit := strings.SplitN(attrStr, "=", 2)
		name := strings.TrimSpace(attrSplit[0])

		// Check for quoted attribute and remove it
		value := strings.TrimSpace(attrSplit[1])
		// If the value is quotes, we know it's a string
		if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
			ad.Set(name, strings.Trim(value, "\""))
		} else if _, err := strconv.Atoi(value); err == nil {
			// If the value is a number, we know it's a number
			intValue, err := strconv.Atoi(value)
			if err == nil {
				ad.Set(name, intValue)
			}
		} else if value == "true" || value == "false" {
			// If the value is a boolean, we know it's a boolean
			ad.Set(name, value == "true")
		} else if _, err := strconv.ParseFloat(value, 64); err == nil {
			// If the value is a float, we know it's a float
			floatValue, err := strconv.ParseFloat(value, 64)
			if err == nil {
				ad.Set(name, floatValue)
			}
		} else {
			// Otherwise, we assume it's a string
			ad.Set(name, value)
		}

	}
	return ad, nil
}

// Split the classad by attribute, at the first semi-colon not in quotes
func attributeSplitFunc(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// Watch out for semi-colons inside quotes
	insideQuotes := false
	for i, curChar := range data {
		if curChar == '"' && !(i > 0 && data[i-1] == '\\') {
			insideQuotes = !insideQuotes
		} else if curChar == ';' && !insideQuotes {
			// Do not return the semi-colon
			// Trim any spaces
			return i + 1, bytes.TrimSpace(data[0:i]), nil
		}
	}
	if atEOF {
		return len(data), bytes.TrimSpace(data), nil
	}
	return 0, nil, nil
}
