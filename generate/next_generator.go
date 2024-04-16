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

// This should not be included in any release of pelican

import (
	"log"
	"os"
	"path/filepath"
)

// Generate a placeholder file under web_ui/frontend/out so that
// we can build Go without error. This is mainly for the linter
// GitHub Action that doesn't need frontend to be built. Refer to
// linter GHA for details.
func GenPlaceholderPathForNext() {
	dir := "../web_ui/frontend/out"
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("error: %v", err)
	}

	filePath := filepath.Join(dir, "placeholder")

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	file.Close()
}

// Copy swagger document from swagger/pelican-swagger.yaml to the web_ui/frontend/app/api directory
func GenSwaggerDoc() {
	src := "../swagger/pelican-swagger.yaml"
	dst := "../web_ui/frontend/app/api/docs/pelican-swagger.yaml"

	swaggerDoc, err := os.ReadFile(src)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	err = os.WriteFile(dst, swaggerDoc, 0644)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}
