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

// This file implements the registry's certificate-authority role (workstream
// WS3 of "reduce origin requirements"). The registry maintains a two-tier PKI:
//
//	federation root (self-signed, long-lived)  ->  registry intermediate  ->  host certs
//
// The root is the federation trust anchor; the intermediate is the working key
// the registry uses to sign short-lived host certificates for approved
// services that cannot obtain a CA-issued certificate on their own. Keeping the
// signing key in an intermediate (rather than signing directly off the root)
// lets a federation later trust multiple registries under one root without
// re-anchoring clients.
//
// This file is deliberately transport-agnostic: it only generates, persists,
// loads, and uses CA material. The HTTP surface that authenticates a service
// and turns its CSR into a certificate lives separately so the policy layer can
// evolve independently of the crypto.
package registry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/database"
)

const (
	caRoleRoot         = "root"
	caRoleIntermediate = "intermediate"

	// caKeyPurpose is the HKDF "info" string that derives the CA-only
	// encryption sub-key from the server master key. Using a dedicated purpose
	// string gives the CA key its own cryptographic domain, isolated from every
	// other sub-key derived from the same master key (e.g. the embedded-issuer
	// HMAC key), so compromise or misuse of one never yields another.
	caKeyPurpose = "pelican-registry-ca-key"

	// Validity windows for the CA tiers. Host certs are short-lived and
	// auto-renewed by the requesting service, so the CA material outlives many
	// host-cert generations.
	rootCAValidity         = 10 * 365 * 24 * time.Hour // ~10 years
	intermediateCAValidity = 5 * 365 * 24 * time.Hour  // ~5 years

	// Default host-certificate lifetime. Short by design: renewal is cheap
	// (the service re-requests) and short lifetimes remove the need for a
	// revocation infrastructure in V2.
	defaultHostCertValidity = 7 * 24 * time.Hour
)

// serialNumberLimit bounds the random 128-bit serial numbers we assign.
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// CertificateAuthority is the persisted CA material for one PKI tier. Exactly
// one row exists per role (root, intermediate); the UNIQUE constraint on role
// enforces this. The private key is stored encrypted at rest (EncryptedKey);
// the certificate is public and stored in the clear.
type CertificateAuthority struct {
	ID           int64     `gorm:"primaryKey;column:id" json:"id"`
	Role         string    `gorm:"column:role;type:text;not null;unique" json:"role"`
	CertPEM      string    `gorm:"column:cert_pem;type:text;not null" json:"certPem"`
	EncryptedKey []byte    `gorm:"column:encrypted_key;not null" json:"-"`
	CreatedAt    time.Time `gorm:"column:created_at;autoCreateTime" json:"createdAt"`
	NotAfter     time.Time `gorm:"column:not_after" json:"notAfter"`
}

func (CertificateAuthority) TableName() string {
	return "certificate_authorities"
}

// caMaterial is the in-memory, parsed form of a CA tier.
type caMaterial struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM string
}

// db returns the provided handle or falls back to the process-wide server DB.
func caDB(db *gorm.DB) *gorm.DB {
	if db != nil {
		return db
	}
	return database.ServerDatabase
}

// caKeyOverride, when non-nil, supplies the 32-byte CA encryption key directly
// instead of deriving it from the server master key. It exists so tests can
// exercise the encrypt-at-rest path without standing up the issuer-key and
// master-key machinery. Production never sets it.
var caKeyOverride []byte

// caEncryptionKey returns the 32-byte symmetric key used to encrypt CA private
// keys at rest: a CA-only sub-key derived (HKDF) from the server master key.
func caEncryptionKey(db *gorm.DB) ([]byte, error) {
	if caKeyOverride != nil {
		return caKeyOverride, nil
	}
	gdb := caDB(db)
	if gdb == nil {
		return nil, errors.New("cannot derive CA encryption key: server database is not initialized")
	}
	masterKey, err := database.LoadOrCreateMasterKey(gdb)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load server master key for CA encryption")
	}
	subKey, err := database.DeriveSubKey(masterKey, caKeyPurpose, 32)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive CA encryption sub-key")
	}
	return subKey, nil
}

// sealCAKey encrypts plaintext with AES-256-GCM under key, returning
// nonce||ciphertext (matching the convention used elsewhere in the codebase,
// e.g. local_cache EncryptDataKey).
func sealCAKey(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create AES cipher for CA key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM for CA key")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "failed to generate nonce for CA key")
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// openCAKey reverses sealCAKey.
func openCAKey(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create AES cipher for CA key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM for CA key")
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("encrypted CA key blob is too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt CA private key")
	}
	return plaintext, nil
}

func newSerialNumber() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate certificate serial number")
	}
	return serial, nil
}

func marshalKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal private key")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func marshalCertPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func parseKeyPEM(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("no PEM block found in CA private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CA private key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf("unexpected CA private key type %T (want ECDSA)", parsed)
	}
	return key, nil
}

func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("no PEM block found in CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CA certificate")
	}
	return cert, nil
}

// generateRoot creates a fresh self-signed federation root CA.
func generateRoot() (*caMaterial, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate root CA key")
	}
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Pelican Federation"},
			CommonName:   "Pelican Federation Root CA",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(rootCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // root -> intermediate -> leaf
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create root CA certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse freshly-created root CA certificate")
	}
	return &caMaterial{cert: cert, key: key, certPEM: marshalCertPEM(der)}, nil
}

// generateIntermediate creates a registry intermediate CA signed by the root.
func generateIntermediate(root *caMaterial) (*caMaterial, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate intermediate CA key")
	}
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Pelican Federation"},
			CommonName:   "Pelican Registry Intermediate CA",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(intermediateCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // intermediate signs only leaves
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, root.cert, &key.PublicKey, root.key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create intermediate CA certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse freshly-created intermediate CA certificate")
	}
	return &caMaterial{cert: cert, key: key, certPEM: marshalCertPEM(der)}, nil
}

func materialToRow(db *gorm.DB, role string, m *caMaterial) (*CertificateAuthority, error) {
	keyPEM, err := marshalKeyPEM(m.key)
	if err != nil {
		return nil, err
	}
	encKey, err := caEncryptionKey(db)
	if err != nil {
		return nil, err
	}
	encrypted, err := sealCAKey(encKey, []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return &CertificateAuthority{
		Role:         role,
		CertPEM:      m.certPEM,
		EncryptedKey: encrypted,
		NotAfter:     m.cert.NotAfter,
	}, nil
}

func rowToMaterial(db *gorm.DB, row *CertificateAuthority) (*caMaterial, error) {
	cert, err := parseCertPEM(row.CertPEM)
	if err != nil {
		return nil, err
	}
	encKey, err := caEncryptionKey(db)
	if err != nil {
		return nil, err
	}
	keyPEM, err := openCAKey(encKey, row.EncryptedKey)
	if err != nil {
		return nil, err
	}
	key, err := parseKeyPEM(string(keyPEM))
	if err != nil {
		return nil, err
	}
	return &caMaterial{cert: cert, key: key, certPEM: row.CertPEM}, nil
}

// loadCA fetches one CA tier. It returns gorm.ErrRecordNotFound when absent.
func loadCA(db *gorm.DB, role string) (*caMaterial, error) {
	var row CertificateAuthority
	if err := caDB(db).Where("role = ?", role).First(&row).Error; err != nil {
		return nil, err
	}
	return rowToMaterial(db, &row)
}

// EnsureFederationCA bootstraps the two-tier PKI if it is not already present.
// It is idempotent and safe to call on every registry startup. Concurrent
// callers race harmlessly: the UNIQUE(role) constraint plus OnConflict-DoNothing
// means only the first writer's material persists, and everyone reloads it.
func EnsureFederationCA(db *gorm.DB) error {
	gdb := caDB(db)
	if gdb == nil {
		return errors.New("cannot ensure federation CA: server database is not initialized")
	}

	// Fast path: both tiers already present.
	if _, err := loadCA(gdb, caRoleIntermediate); err == nil {
		return nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.Wrap(err, "failed to check for existing intermediate CA")
	}

	// Load or create the root first.
	root, err := loadCA(gdb, caRoleRoot)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Info("No federation root CA found; generating a new self-signed root")
		root, err = generateRoot()
		if err != nil {
			return err
		}
		rootRow, err := materialToRow(gdb, caRoleRoot, root)
		if err != nil {
			return err
		}
		// DoNothing on conflict: another process may have inserted the root
		// between our read and write. We reload below to converge on it.
		if err := gdb.Clauses(clause.OnConflict{DoNothing: true}).Create(rootRow).Error; err != nil {
			return errors.Wrap(err, "failed to persist federation root CA")
		}
		if root, err = loadCA(gdb, caRoleRoot); err != nil {
			return errors.Wrap(err, "failed to reload federation root CA after creation")
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to load federation root CA")
	}

	// Create the intermediate signed by whichever root is now canonical.
	log.Info("Generating a new registry intermediate CA signed by the federation root")
	intermediate, err := generateIntermediate(root)
	if err != nil {
		return err
	}
	intRow, err := materialToRow(gdb, caRoleIntermediate, intermediate)
	if err != nil {
		return err
	}
	if err := gdb.Clauses(clause.OnConflict{DoNothing: true}).Create(intRow).Error; err != nil {
		return errors.Wrap(err, "failed to persist registry intermediate CA")
	}
	return nil
}

// HostCertRequest describes a request to mint a host certificate.
//
// AuthorizedNames is the exact SAN set the registry will stamp into the
// certificate — NOT a filter over the CSR. For a Pelican service this is its
// unique service-ID slug (a short, randomly-generated identifier the registry
// assigns). Peers authenticate the TLS connection against that slug — set as
// the client's expected ServerName — rather than against the origin's IP
// address, so reaching a service by IP (WS2) and authenticating it by slug
// (WS3) are orthogonal and **IP SANs are never issued**. The CSR supplies only
// the host public key (and proves possession of the host key via its
// self-signature); any SANs it requests are ignored, so a requester can never
// obtain a name it is not entitled to.
type HostCertRequest struct {
	CSR             *x509.CertificateRequest
	AuthorizedNames []string
	// TTL is the certificate lifetime; zero uses defaultHostCertValidity.
	TTL time.Duration
}

// SignHostCertificate authenticates nothing — callers must have already
// verified the requester's identity and computed AuthorizedNames. It verifies
// the CSR self-signature (proving the requester holds the host private key),
// then signs a leaf certificate whose SANs are exactly AuthorizedNames, using
// the registry intermediate. The returned PEM is the leaf followed by the
// intermediate (a chain a TLS server can present directly, which also aids
// path resolution for peers that only trust the root); the root is distributed
// separately as a trust anchor via GetCABundlePEM and the federation metadata.
func SignHostCertificate(db *gorm.DB, req HostCertRequest) (chainPEM string, err error) {
	if req.CSR == nil {
		return "", errors.New("host certificate request is missing a CSR")
	}
	if err := req.CSR.CheckSignature(); err != nil {
		return "", errors.Wrap(err, "CSR signature verification failed")
	}

	// The certificate's SANs are exactly the authorized names (the slug). The
	// CSR's own SAN requests are deliberately ignored — the requester cannot
	// influence which identity it is granted.
	if len(req.CSR.IPAddresses) > 0 {
		log.Warnf("Ignoring %d IP SAN(s) in host certificate request: services authenticate by slug, not IP", len(req.CSR.IPAddresses))
	}
	dnsNames := make([]string, 0, len(req.AuthorizedNames))
	seen := make(map[string]struct{}, len(req.AuthorizedNames))
	for _, name := range req.AuthorizedNames {
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		dnsNames = append(dnsNames, name)
	}
	if len(dnsNames) == 0 {
		return "", errors.New("host certificate request has no authorized SANs")
	}

	intermediate, err := loadCA(db, caRoleIntermediate)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errors.New("registry intermediate CA is not initialized; call EnsureFederationCA first")
		}
		return "", errors.Wrap(err, "failed to load registry intermediate CA")
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultHostCertValidity
	}
	serial, err := newSerialNumber()
	if err != nil {
		return "", err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, intermediate.cert, req.CSR.PublicKey, intermediate.key)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign host certificate")
	}
	return marshalCertPEM(der) + intermediate.certPEM, nil
}

// GetCABundlePEM returns the trust anchor(s) a client or peer must trust to
// validate certificates issued by this registry: the federation root. The
// intermediate is delivered in-band with each host certificate chain, so the
// bundle is just the root.
func GetCABundlePEM(db *gorm.DB) (string, error) {
	root, err := loadCA(db, caRoleRoot)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errors.New("federation root CA is not initialized; call EnsureFederationCA first")
		}
		return "", errors.Wrap(err, "failed to load federation root CA")
	}
	return root.certPEM, nil
}
