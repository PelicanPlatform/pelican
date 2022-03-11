package classads

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strings"
)

type ClassAd struct {
	attributes map[string]interface{}
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
	c.attributes[name] = value
}

// ReadClassAd reads a ClassAd from the given reader.
func ReadClassAd(reader io.Reader) ([]ClassAd, error) {
	var ads []ClassAd
	scanner := bufio.NewScanner(reader)
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexByte(data, ']'); i >= 0 {
			return i + 1, data[0 : i+1], nil
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

	// Split by "\n" or ";"
	splitter := regexp.MustCompile(`[\n;]`)
	splitted := splitter.Split(line, -1)

	// For each attribute, split by the first "="
	for _, attrStr := range splitted {
		attrSplit := strings.SplitN(attrStr, "=", 2)
		name := strings.TrimSpace(attrSplit[0])
		// Check for quoted attribute and remove it
		value := strings.TrimSpace(attrSplit[1])
		value = strings.TrimPrefix(value, "\"")
		value = strings.TrimSuffix(value, "\"")
		ad.Set(name, value)
	}
	return ad, nil
}
