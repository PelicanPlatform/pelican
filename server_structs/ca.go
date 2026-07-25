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

package server_structs

// Protocol types and constants shared by the registry certificate authority
// (WS3) and its clients. Kept in server_structs so both the registry server
// package and the registry client can reference one definition.

const (
	// HostCertAudience is the audience the host-certificate request token must
	// carry, pinning the token to the registry CA so a token minted by the same
	// key for another purpose cannot be replayed here.
	HostCertAudience = "pelican-registry-host-certificate"

	// HostCertCSRHashClaim is the private JWT claim that binds the token to a
	// specific CSR: hex(SHA-256(CSR DER)). The registry recomputes it over the
	// presented CSR and rejects a mismatch.
	HostCertCSRHashClaim = "csr_sha256"

	// HostCertificateEndpoint is the registry path (relative to the registry
	// API root) that issues host certificates.
	HostCertificateEndpoint = "issueHostCertificate"

	// CABundleEndpoint is the registry path (relative to the registry API root)
	// serving the public federation root certificate.
	CABundleEndpoint = "ca.pem"
)

// IssueHostCertRequest is the POST body for the host-certificate endpoint.
type IssueHostCertRequest struct {
	Prefix string `json:"prefix"`
	CSR    string `json:"csr"`   // PEM-encoded certificate signing request
	Token  string `json:"token"` // JWT signed by the registered key
}

// IssueHostCertResponse is the success body: the PEM leaf+intermediate chain.
type IssueHostCertResponse struct {
	Certificate string `json:"certificate"`
}
