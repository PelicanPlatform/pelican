/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"gopkg.in/yaml.v3"
)

// TODO: might need to change this
type ErrorType struct {
	Raw       string
	Display   string
	ExitCode  int
	Code      int
	Retryable bool
}

// TODO: change to 5 (for minor codes)
var requiredErrorKeys = [4]string{"code", "clientExitCode", "description", "retryable"}

func GenErrorCodes() {
	filename, _ := filepath.Abs("../docs/error_codes.yaml")
	yamlFile, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer yamlFile.Close()

	decoder := yaml.NewDecoder(yamlFile)

	var values []interface{}

	for {
		var value map[string]interface{}
		if err := decoder.Decode(&value); err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Errorf("document decode failed"))
		}
		values = append(values, value)
	}

	errors := make([]ErrorType, 0)

	for i := 0; i < len(values); i++ {
		entry := values[i].(map[string]interface{})

		errorType, ok := entry["type"].(string)
		if !ok {
			panic(fmt.Sprintf("Error entry at position %d is missing the type attribute", i))
		}
		for _, keyName := range requiredErrorKeys {
			if _, ok := entry[keyName]; !ok {
				panic(fmt.Sprintf("Parameter entry '%s' is missing required key '%s'", errorType, keyName))
			}
		}
		camelScopeName := handleCaseConversion(errorType)
		scopeNameInSnake := strings.Replace(camelScopeName, ".", "_", 1)
		r := []rune(scopeNameInSnake)
		r[0] = unicode.ToUpper(r[0])
		displayName := string(r)

		exitCode, ok := entry["clientExitCode"].(int)
		if !ok {
			panic(fmt.Sprintf("Error entry at position %d is missing the exit code attribute", i))
		}

		code, ok := entry["code"].(int)
		if !ok {
			panic(fmt.Sprintf("Error entry at position %d is missing the code attribute", i))
		}

		retryable, ok := entry["retryable"].(bool)
		if !ok {
			panic(fmt.Sprintf("Error entry at position %d is missing the retryable attribute", i))
		}

		errors = append(errors, ErrorType{Raw: errorType, Display: displayName, ExitCode: exitCode,
			Code: code, Retryable: retryable})
	}

	// Create the fike to be generated
	f, err := os.Create("../error_codes/error_codes.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = errorTemplate.Execute(f, struct {
		PelicanErrors []ErrorType
	}{
		PelicanErrors: errors,
	})

	if err != nil {
		panic(err)
	}
}

var errorTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.
/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package error_codes

import (
	"fmt"
)

type PelicanError struct {
	errorType string
	exitCode  int
	code      int
	retryable bool
	err       error
}

{{- range $idx, $pelicanError := .PelicanErrors}}
func New{{$pelicanError.Display}}Error(err error) *PelicanError {
	return &PelicanError{
		errorType: "{{$pelicanError.Raw}}",
		exitCode: {{$pelicanError.ExitCode}},
		code: {{$pelicanError.Code}},
		retryable: {{$pelicanError.Retryable}},
		err: err,
	}
}
{{- end}}

// function that maps the error to the exit code
func (e *PelicanError) ExitCode() int {
	return e.exitCode
}

func (e *PelicanError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s Error: Error code %d: %v", e.errorType, e.code, e.err)
	}
	return e.errorType
}

func (e *PelicanError) UnWrap() error {
	return e.err
}

func (e *PelicanError) Wrap(err error) *PelicanError {
	e.err = err
	return e
}
`))