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

// These templates are converted from the JSP files in oa4mp/resources/jsp-overrides/
// to Go html/template format.

const pelicanCSS = `
    body {
      font-family: 'Poppins', 'Helvetica Neue', Arial, sans-serif;
      background-color: #ffffff;
      margin: 0;
      padding: 0;
      position: relative;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
    }
    .background-effect {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: conic-gradient(from 180deg at 80% 80%, #16abff 0deg, #0885ff 55deg, #54d6ff 120deg, #0071ff 160deg, #0071ff 1turn);
      opacity: 20%;
      z-index: -1;
      filter: blur(20px);
    }
    h2 {
      color: #0885ff;
      text-align: center;
    }
    p {
      text-align: center;
      font-size: 16px;
    }
    .pelican-button {
      background-color: #0885ff;
      color: white;
      border: none;
      padding: 10px 20px;
      cursor: pointer;
      font-size: 14px;
      border-radius: 5px;
    }
    .pelican-button:hover {
      background-color: #005bb5;
    }
    a {
      text-decoration: none;
    }
    .content-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      margin: 20px;
    }
    .client-info {
      background-color: white;
      padding: 20px;
      border-radius: 5px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      margin-bottom: 20px;
    }
    .button-container {
      display: flex;
      justify-content: center;
      gap: 10px;
      margin-bottom: 20px;
    }
    .footer-logo {
      text-align: center;
      margin-top: 40px;
    }
    input[type="text"] {
      padding: 10px;
      font-size: 18px;
      letter-spacing: 4px;
      text-align: center;
      border: 2px solid #0885ff;
      border-radius: 5px;
      width: 200px;
      text-transform: uppercase;
    }
    .retry-message {
      color: #ff0000;
      font-weight: bold;
      text-align: center;
      margin-top: 10px;
    }
`

// deviceConsentTemplate is the Go template for the device code entry/consent page.
// Converted from oa4mp/resources/jsp-overrides/device-consent.jsp
const deviceConsentTemplate = `<!DOCTYPE html>
<html>
<head>
  <title>Pelican Device Authorization</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:ital@0;1&display=swap" rel="stylesheet">
  <style>` + pelicanCSS + `</style>
</head>
<body>
<div class="background-effect"></div>
<main>
  <div class="content-container">
    <h2>Pelican Device Authorization</h2>
    <p>Enter the code displayed on your device to authorize access.</p>
    <form method="POST" action="{{.FormAction}}">
      <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
      <div class="client-info">
        <p>Enter the user code from your CLI:</p>
        <div style="text-align: center; margin: 20px 0;">
          <input type="text" id="user_code" name="user_code" value="{{.UserCode}}"
                 placeholder="XXXX-XXXX" required autofocus maxlength="9"
                 pattern="[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}">
        </div>
      </div>
      <div class="button-container">
        <input type="submit" name="action" value="approve" class="pelican-button"/>
        <input type="submit" name="action" value="deny" class="pelican-button"/>
      </div>
    </form>
  </div>
</main>
<div class="footer-logo">
  <img height="80" src="https://pelicanplatform.org/static/images/PelicanPlatformLogo_Icon.png" alt="Pelican Logo">
</div>
</body>
</html>`

// deviceOkTemplate is rendered after successful device code approval.
// Converted from oa4mp/resources/jsp-overrides/device-ok.jsp
const deviceOkTemplate = `<!DOCTYPE html>
<html>
<head>
  <title>Pelican Device Authorized</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:ital@0;1&display=swap" rel="stylesheet">
  <style>` + pelicanCSS + `</style>
</head>
<body>
<div class="background-effect"></div>
<main>
  <div class="content-container">
    <h2>User Code Accepted!</h2>
    <p>Continue on the CLI.</p>
  </div>
</main>
<div class="footer-logo">
  <img height="80" src="https://pelicanplatform.org/static/images/PelicanPlatformLogo_Icon.png" alt="Pelican Logo">
</div>
</body>
</html>`

// deviceFailTemplate is rendered when device code approval fails.
// Converted from oa4mp/resources/jsp-overrides/device-fail.jsp
const deviceFailTemplate = `<!DOCTYPE html>
<html>
<head>
  <title>Pelican Device Authorization Failed</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:ital@0;1&display=swap" rel="stylesheet">
  <style>` + pelicanCSS + `</style>
</head>
<body>
<div class="background-effect"></div>
<main>
  <div class="content-container">
    <h2>User Code Denied!</h2>
    {{if .ErrorMessage}}
    <p>{{.ErrorMessage}}</p>
    {{else}}
    <p>You have exceeded the number of retry attempts for entering a code.</p>
    {{end}}
  </div>
</main>
<div class="footer-logo">
  <img height="80" src="https://pelicanplatform.org/static/images/PelicanPlatformLogo_Icon.png" alt="Pelican Logo">
</div>
</body>
</html>`
