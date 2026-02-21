/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package issuer

import (
	"embed"
	"html/template"
)

// resourceFS embeds the HTML templates and CSS from the resources/ directory.
//
//go:embed resources/*.html resources/*.css
var resourceFS embed.FS

// pelicanCSS is the shared stylesheet loaded from resources/pelican.css.
var pelicanCSS string

// Parsed templates, initialised once at program start.
var (
	deviceConsentTmpl *template.Template
	deviceOkTmpl      *template.Template
	deviceFailTmpl    *template.Template
)

func init() {
	css, err := resourceFS.ReadFile("resources/pelican.css")
	if err != nil {
		panic("embedded-oauth: failed to read resources/pelican.css: " + err.Error())
	}
	pelicanCSS = string(css)

	mustParse := func(name, file string) *template.Template {
		data, err := resourceFS.ReadFile(file)
		if err != nil {
			panic("embedded-oauth: failed to read " + file + ": " + err.Error())
		}
		t, err := template.New(name).Parse(string(data))
		if err != nil {
			panic("embedded-oauth: failed to parse " + file + ": " + err.Error())
		}
		return t
	}

	deviceConsentTmpl = mustParse("device-consent", "resources/device_consent.html")
	deviceOkTmpl = mustParse("device-ok", "resources/device_ok.html")
	deviceFailTmpl = mustParse("device-fail", "resources/device_fail.html")
}
