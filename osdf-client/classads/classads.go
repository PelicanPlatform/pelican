package classads

import (
	"bufio"
	"bytes"
	"fmt"
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
		// Parse the classad
		fmt.Println("Classad: " + line)
		ad, err := ParseClassAd(line)
		if err != nil {
			return nil, err
		}
		ads = append(ads, ad)

	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return nil, nil
}

func ParseClassAd(line string) (ClassAd, error) {
	var ad ClassAd
	ad.attributes = make(map[string]interface{})
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "[")
	line = strings.TrimSuffix(line, "]")
	splitter := regexp.MustCompile(`[\n;]`)
	splitted := splitter.Split(line, -1)
	fmt.Println(splitted)
	fmt.Println(len(splitted))
	return ad, nil
}
