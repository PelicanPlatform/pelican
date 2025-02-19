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

package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

type IssuerKeys struct {
	// CurrentKey is the private key used to sign tokens and payloads. It corresponds to the
	// private key with the highest lexicographical filename among the legacy key file
	// (if present) and all .pem files in IssuerKeyDirectory.
	CurrentKey jwk.Key

	// AllKeys holds all valid private keys as a [keyID:key] map, including those from .pem files
	// in IssuerKeyDirectory and legacy key file at IssuerKey (if exists). A token or
	// payload signature is considered valid if any of these keys could have produced it.
	AllKeys map[string]jwk.Key
}

var (
	issuerKeys atomic.Pointer[IssuerKeys]

	// Used to ensure initialization func init() is only called once
	initOnce sync.Once
)

// Set a private key as the issuer key
func setIssuerKey(key jwk.Key) {
	newKeys := IssuerKeys{
		CurrentKey: key,
		AllKeys:    getIssuerPrivateKeysCopy(), // Get a copy of the existing keys
	}
	newKeys.AllKeys[key.KeyID()] = key // Add the new key to the copy
	issuerKeys.Store(&newKeys)
}

// Resets the entire keys struct, including current and all keys. CurrentKey is implicitly set to nil
func ResetIssuerPrivateKeys() {
	issuerKeys.Store(&IssuerKeys{
		AllKeys: make(map[string]jwk.Key),
	})
}

// Safely load the current map and create a copy for modification
func getIssuerPrivateKeysCopy() map[string]jwk.Key {
	currentKeysPtr := issuerKeys.Load()
	if currentKeysPtr == nil {
		return make(map[string]jwk.Key)
	}

	currentKeys := *currentKeysPtr
	newMap := make(map[string]jwk.Key, len(currentKeys.AllKeys))
	for k, v := range currentKeys.AllKeys {
		newMap[k] = v
	}
	return newMap
}

// Read the current map
func GetIssuerPrivateKeys() map[string]jwk.Key {
	keysPtr := issuerKeys.Load()
	if keysPtr == nil {
		return make(map[string]jwk.Key)
	}

	return (*keysPtr).AllKeys
}

// Helper function to create a directory and set proper permissions to save private keys
func createDirForKeys(dir string) error {
	gid, err := GetDaemonGID()
	if err != nil {
		return errors.Wrap(err, "failed to get daemon gid")
	}
	if err := MkdirAll(dir, 0750, -1, gid); err != nil {
		return errors.Wrapf(err, "failed to set the permission of %s", dir)
	}
	return nil
}

// Return a pointer to an ECDSA private key or RSA private key read from keyLocation.
//
// This can be used to load ECDSA or RSA private key for various purposes,
// including IssuerKey, TLSKey, and TLSCAKey
//
// If allowRSA is false, an RSA key in the keyLocation gives error
func LoadPrivateKey(keyLocation string, allowRSA bool) (crypto.PrivateKey, error) {
	rest, err := os.ReadFile(keyLocation)
	if err != nil {
		return nil, err
	}

	var privateKey crypto.PrivateKey
	var block *pem.Block

	keyExists := false

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		} else if block.Type == "PRIVATE KEY" {
			genericPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			switch key := genericPrivateKey.(type) {
			case *ecdsa.PrivateKey:
				privateKey = key
			case *rsa.PrivateKey:
				if allowRSA {
					privateKey = key
				} else {
					return nil, fmt.Errorf("RSA type private key in PKCS #8 form is not allowed for %s. Use an ECDSA key instead.", keyLocation)
				}
			default:
				return nil, fmt.Errorf("Unsupported private key type: %T in the private key file %s with PEM block type as PRIVATE KEY", key, keyLocation)
			}
			break
		} else if block.Type == "RSA PRIVATE KEY" {
			if !allowRSA {
				return nil, fmt.Errorf("RSA type private key is not allowed for %s. Use an ECDSA key instead.", keyLocation)
			} else {
				rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return nil, err
				}
				privateKey = rsaPrivateKey
			}
		} else {
			keyExists = true
		}
	}
	if privateKey == nil {
		if keyExists {
			return nil, fmt.Errorf("Private key file, %v, contains unsupported key type", keyLocation)
		} else {
			return nil, fmt.Errorf("Private key file, %v, contains no private key", keyLocation)
		}
	}
	return privateKey, nil
}

// Check if a file exists at keyLocation, return if so; otherwise, generate
// and writes a PEM-encoded ECDSA-encrypted private key with elliptic curve assigned
// by curve
func GeneratePrivateKey(keyLocation string, curve elliptic.Curve, allowRSA bool) error {
	if keyLocation == "" {
		return errors.New("failed to generate private key: key location is empty")
	}
	user, err := GetPelicanUser()
	if err != nil {
		return err
	}

	if file, err := os.Open(keyLocation); err == nil {
		defer file.Close()
		// Make sure key is valid if there is one
		if _, err := LoadPrivateKey(keyLocation, allowRSA); err != nil {
			return err
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(err, "Failed to load private key due to I/O error")
	}

	// If we're generating a new key, log a warning in case the user intended to pass an existing key (maybe they made a typo)
	log.Warningf("Will generate a new private key at location: %v", keyLocation)

	keyDir := filepath.Dir(keyLocation)
	if err := MkdirAll(keyDir, 0750, -1, user.Gid); err != nil {
		return err
	}
	// In this case, the private key file doesn't exist.
	file, err := os.OpenFile(keyLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return errors.Wrap(err, "Failed to create new private key file at "+keyLocation)
	}
	defer file.Close()

	// Windows does not have "chown", has to work differently
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		cmd := exec.Command("icacls", keyLocation, "/grant", user.Username+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v: %s",
				keyLocation, user.Groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(keyLocation, user.Uid, user.Gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
				keyLocation, user.Groupname)
		}
	}

	return generatePrivateKeyToFile(file, curve)
}

// Write a PEM-encoded private key to an open file
func generatePrivateKeyToFile(file *os.File, curve elliptic.Curve) error {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	priv_block := pem.Block{Type: "PRIVATE KEY", Bytes: bytes}
	if err = pem.Encode(file, &priv_block); err != nil {
		return err
	}
	return nil
}

// Helper function to generate a Certificate Authority (CA) certificate and its private key
// for non-production environment so that we can use the private key of the CA
// to sign the host certificate
func GenerateCACert() error {
	user, err := GetPelicanUser()
	if err != nil {
		return err
	}

	// If you provide a CA, you must also provide its private key in order for
	// GenerateCert to sign the  host certificate by that key, or we will generate
	// a new CA
	tlsCACert := param.Server_TLSCACertificateFile.GetString()
	if file, err := os.Open(tlsCACert); err == nil {
		file.Close()
		tlsCAKey := param.Server_TLSCAKey.GetString()
		if file, err := os.Open(tlsCAKey); err == nil {
			file.Close()
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.Wrap(err, "Failed to load TLS CA private key due to I/O error")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(err, "Failed to load TLS CA certificate due to I/O error")
	}

	// No existing CA cert present, generate a new CA root certificate and private key
	tlsCertDir := filepath.Dir(tlsCACert)
	if err := MkdirAll(tlsCertDir, 0755, user.Uid, user.Gid); err != nil {
		return err
	}

	tlsCAKey := param.Server_TLSCAKey.GetString()
	// We allow RSA type key but if the key DNE, we will still generate an ECDSA key
	if err := GeneratePrivateKey(tlsCAKey, elliptic.P256(), true); err != nil {
		return err
	}
	privateKey, err := LoadPrivateKey(tlsCAKey, true)
	if err != nil {
		return err
	}
	var pubKey any
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &(key.PublicKey)
	case *ecdsa.PrivateKey:
		pubKey = &(key.PublicKey)
	default:
		return errors.Errorf("unsupported private key type: %T", key)
	}

	log.Debugln("Server.TLSCACertificateFile does not exist. Will generate a new CA certificate for the server")
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	hostname := param.Server_Hostname.GetString()
	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pelican CA"},
			CommonName:   hostname,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	template.DNSNames = []string{hostname}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey,
		privateKey)
	if err != nil {
		return errors.Wrap(err, "error creating a CA cert")
	}
	file, err := os.OpenFile(tlsCACert, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer file.Close()

	// Windows does not have "chown", has to work differently
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		cmd := exec.Command("icacls", tlsCACert, "/grant", user.Username+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v: %s",
				tlsCACert, user.Groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(tlsCACert, user.Uid, user.Gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
				tlsCACert, user.Groupname)
		}
	}

	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return nil
}

// Read a PEM-encoded TLS certificate file, parse and return the first
// certificate appeared in the chain. Return error if there's no cert
// present in the file
func LoadCertificate(certFile string) (*x509.Certificate, error) {
	rest, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	var cert *x509.Certificate
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		} else if block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if cert == nil {
		return nil, fmt.Errorf("certificate file, %v, contains no certificate", certFile)
	}
	return cert, nil
}

// Generate a TLS certificate (host certificate) and its private key
// for non-production environment if the required TLS files are not present
func GenerateCert() error {
	user, err := GetPelicanUser()
	if err != nil {
		return err
	}

	tlsCertPrivateKeyExists := false

	tlsCert := param.Server_TLSCertificateChain.GetString()
	if file, err := os.Open(tlsCert); err == nil {
		file.Close()
		// Check that the matched-pair private key is present
		tlsKey := param.Server_TLSKey.GetString()
		if file, err := os.Open(tlsKey); err == nil {
			file.Close()
			tlsCertPrivateKeyExists = true
			// Check that CA is also present
			caCert := param.Server_TLSCACertificateFile.GetString()
			if _, err := os.Open(caCert); err == nil {
				file.Close()
				// Check that the CA is a valid CA
				if _, err := LoadCertificate(caCert); err != nil {
					return errors.Wrap(err, "Failed to load CA cert")
				} else {
					// TODO: Check that the private key is a pair of the server cert

					// Here we return based on the check that
					// 1. TLS cert is present
					// 2. The private key of TLS cert if present
					// 3. The CA is present
					return nil
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return errors.Wrap(err, "Failed to load TLS CA cert due to I/O error")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.Wrap(err, "Failed to load TLS host private key due to I/O error")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(err, "Failed to load TLS host certificate due to I/O error")
	}

	// In this case, no host certificate exists - we should generate our own.

	if err := GenerateCACert(); err != nil {
		return err
	}
	caCert, err := LoadCertificate(param.Server_TLSCACertificateFile.GetString())
	if err != nil {
		return err
	}

	// However, if only CA is missing but TLS cert and private key are present, we simply
	// generate the CA and return
	if tlsCertPrivateKeyExists {
		log.Debug("TLS Certificate and its private key are present. Generated a CA and returns.")
		return nil
	}

	tlsCertDir := filepath.Dir(tlsCert)
	if err := MkdirAll(tlsCertDir, 0755, user.Uid, user.Gid); err != nil {
		return err
	}

	tlsKey := param.Server_TLSKey.GetString()

	// In case we didn't generate TLS private key
	if err := GeneratePrivateKey(tlsKey, elliptic.P256(), true); err != nil {
		return err
	}
	privateKey, err := LoadPrivateKey(tlsKey, true)
	if err != nil {
		return err
	}

	// The private key of CA will always be present
	caPrivateKey, err := LoadPrivateKey(param.Server_TLSCAKey.GetString(), true)
	if err != nil {
		return err
	}

	var caPubKey any
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		caPubKey = &(key.PublicKey)
	case *ecdsa.PrivateKey:
		caPubKey = &(key.PublicKey)
	default:
		return errors.Errorf("unsupported private key type: %T", key)
	}

	log.Debugln("Server.TLSCertificateChain and/or Server.TLSKey do not exist. Will generate a new host certificate and its private key for the server")
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	hostname := param.Server_Hostname.GetString()
	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pelican"},
			CommonName:   hostname,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = []string{hostname}

	// If there's pre-existing CA certificates, self-sign instead of using the generated CA
	signingCert := caCert
	signingKey := caPrivateKey

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, signingCert, caPubKey,
		signingKey)
	if err != nil {
		return errors.Wrap(err, "error creating a TLS cert")
	}
	file, err := os.OpenFile(tlsCert, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer file.Close()

	// Windows does not have "chown", has to work differently
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		cmd := exec.Command("icacls", tlsCert, "/grant", user.Username+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v: %s",
				tlsCert, user.Groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(tlsCert, user.Uid, user.Gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
				tlsCert, user.Groupname)
		}
	}

	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return nil
}

// Helper function to initialize the in-memory map to save all private keys
func initKeysMap() {
	initialMap := make(map[string]jwk.Key)
	issuerKeys.Store(&IssuerKeys{
		AllKeys: initialMap,
	})
}

// Helper function to load one .pem file from specified filename
func loadSinglePEM(path string) (jwk.Key, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read key file")
	}

	key, err := jwk.ParseKey(contents, jwk.WithPEM(true))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse issuer key file %v", path)
	}

	// Add the algorithm to the key, needed for verifying tokens elsewhere
	if err := key.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, errors.Wrap(err, "failed to set algorithm")
	}

	// Ensure key has an ID
	if err := jwk.AssignKeyID(key); err != nil {
		return nil, errors.Wrap(err, "failed to assign key ID")
	}

	return key, nil
}

// Helper function to load/refresh all key files from both legacy IssuerKey file and specified directory
// find the most recent private key based on lexicographical order of their filenames
func loadPEMFiles(dir string) (jwk.Key, error) {
	var firstKey jwk.Key
	var firstFileName string
	latestKeys := getIssuerPrivateKeysCopy()

	// Load legacy private key if it exists - parsing the file at IssuerKey act as if it is included in IssuerKeysDirectory
	issuerKeyPath := param.IssuerKey.GetString()
	if issuerKeyPath != "" {
		if _, err := os.Stat(issuerKeyPath); err == nil {
			issuerKey, err := loadSinglePEM(issuerKeyPath)
			if err != nil {
				log.Warnf("Failed to load key %s: %v", issuerKeyPath, err)
			} else {
				latestKeys[issuerKey.KeyID()] = issuerKey
				if firstFileName == "" || filepath.Base(issuerKeyPath) < firstFileName {
					firstFileName = filepath.Base(issuerKeyPath)
					firstKey = issuerKey
				}
			}
		}
	}

	if dir == "" && issuerKeyPath == "" {
		return nil, errors.New("no private key file or directory specified")
	}

	if dir != "" {
		// Ensure input directory dir exists, if not, create it with proper permissions
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := createDirForKeys(dir); err != nil {
				return nil, errors.Wrapf(err, "failed to create directory and set permissions: %s", dir)
			}
		}
		// Traverse the directory for .pem files in lexical order
		err := filepath.WalkDir(dir, func(path string, dirEnt fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Do not recurse into directories
			if (path != dir) && dirEnt.IsDir() {
				return filepath.SkipDir
			}
			if dirEnt.Type().IsRegular() && filepath.Ext(dirEnt.Name()) == ".pem" {
				// Parse the private key in this file and add to the in-memory keys map
				key, err := loadSinglePEM(path)
				if err != nil {
					log.Warnf("Failed to load key %s: %v", path, err)
					return nil // Skip this file and continue
				}

				latestKeys[key.KeyID()] = key

				// Update the most recent key based on lexicographical order of filenames
				if firstFileName == "" || dirEnt.Name() < firstFileName {
					firstFileName = dirEnt.Name()
					firstKey = key
				}
			}
			return nil
		})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to traverse directory %s that stores private keys", dir)
		}
	}

	// Create a new private key and set as issuer key when neither legacy private key at IssuerKey
	// nor any .pem file at IssuerKeysDirectory exists
	if len(latestKeys) == 0 || firstKey == nil {
		newKey, err := generatePEMandSetIssuerKey(dir)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a new .pem file to save private key")
		}
		return newKey, nil
	}

	// Save current key and all up-to-date valid private keys and the in-memory issuerKeys
	newKeys := IssuerKeys{
		CurrentKey: firstKey,
		AllKeys:    latestKeys,
	}
	issuerKeys.Store(&newKeys)
	log.Debugf("Set private key %s as the issuer key", firstKey.KeyID())

	return firstKey, nil
}

// Create a new .pem file (combining GeneratePrivateKey and LoadPrivateKey functions)
func GeneratePEM(dir string) (key jwk.Key, err error) {
	var fname string
	var keyFile *os.File
	if dir == "" {
		issuerKeyLocation := param.IssuerKey.GetString()
		if issuerKeyLocation == "" {
			err = errors.New("no private key file or directory specified")
			return
		}
		log.Debugln("Generating new private key in the legacy IssuerKey file", issuerKeyLocation)
		fname = issuerKeyLocation
		keyFile, err = os.OpenFile(issuerKeyLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			err = errors.Wrap(err, "failed to open issuer key file")
			return
		}
	} else {
		// Generate a unique filename using a POSIX mkstemp-like logic
		// Create a temp file, store its filename, then immediately delete this temp file
		filenamePattern := fmt.Sprintf("pelican_generated_%d_*.pem",
			time.Now().UnixNano())
		if err = createDirForKeys(dir); err != nil {
			err = errors.Wrapf(err, "failed to create directory and set permissions: %s", dir)
			return
		}
		keyFile, err = os.CreateTemp(dir, filenamePattern)
		if err != nil {
			err = errors.Wrap(err, "failed to remove temp file")
			return
		}
		fname = keyFile.Name()
		log.Debugln("Generating new private key in the IssuerKeys directory at", fname)
	}
	defer keyFile.Close()

	if err = generatePrivateKeyToFile(keyFile, elliptic.P256()); err != nil {
		return nil, errors.Wrapf(err, "failed to generate private key in file %s", fname)
	}

	if key, err = loadSinglePEM(fname); err != nil {
		log.Errorf("Failed to load key %s: %v", fname, err)
		err = errors.Wrapf(err, "failed to load key from %s", fname)
		return
	}

	log.Debugf("Generated private key with key ID %s", key.KeyID())
	return
}

// Generate a new .pem file and then set the private key it contains as the issuer key
func generatePEMandSetIssuerKey(dir string) (jwk.Key, error) {
	newKey, err := GeneratePEM(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create a new .pem file to save private key")
	}

	setIssuerKey(newKey)

	return newKey, nil
}

// Re-scan the disk to load the current valid private keys, return the issuer key to sign tokens it issues
// The issuer key is the key with the highest lexicographical filename
func loadIssuerPrivateKey(issuerKeysDir string) (jwk.Key, error) {
	// Ensure initKeysMap is only called once across the program’s runtime
	initOnce.Do(func() {
		initKeysMap()
	})

	issuerKey, err := loadPEMFiles(issuerKeysDir)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to re-scan %s to load .pem files and set the key file with the
		highest lexicographical order as the current issuer key`, issuerKeysDir)
	}

	return issuerKey, err
}

// Helper function to load the issuer/server's public key for other servers
// to verify the token signed by this server. Only intended to be called internally
func loadIssuerPublicJWKS(existingJWKS string, issuerKeysDir string) (jwk.Set, error) {
	jwks := jwk.NewSet()
	if existingJWKS != "" {
		var err error
		jwks, err = jwk.ReadFile(existingJWKS)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read issuer JWKS file")
		}
	}
	keys := GetIssuerPrivateKeys()
	if len(keys) == 0 {
		// Retrieve issuerPrivateKeys if it's non-empty, or find and parse all private key
		// files on disk, or generate a new private key
		_, err := loadIssuerPrivateKey(issuerKeysDir)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to load issuer private JWK")
		}
		// Reload the keys after the key refresh/creation
		keys = GetIssuerPrivateKeys()
	}

	// Traverse all private keys and add their public keys to the JWKS
	for _, key := range keys {
		pkey, err := jwk.PublicKeyOf(key)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to generate public key from key %s", key.KeyID())
		}

		if err = jwks.AddKey(pkey); err != nil {
			return nil, errors.Wrapf(err, "Failed to add public key %s to new JWKS", key.KeyID())
		}
	}
	return jwks, nil
}

// Return the private JWK for the server to sign tokens and payloads
func GetIssuerPrivateJWK() (jwk.Key, error) {
	keysPtr := issuerKeys.Load()
	issuerKeysDir := param.IssuerKeysDirectory.GetString()

	// Re-scan the private keys dir when no issuer key in memory
	if keysPtr == nil || keysPtr.CurrentKey == nil {
		newKey, err := loadIssuerPrivateKey(issuerKeysDir)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to load issuer private key")
		}
		newKeys := IssuerKeys{
			CurrentKey: newKey,
			AllKeys:    map[string]jwk.Key{newKey.KeyID(): newKey},
		}

		issuerKeys.Store(&newKeys)

		keysPtr = issuerKeys.Load() // Reload after store
	}
	return (*keysPtr).CurrentKey, nil
}

// Check if a valid JWKS file exists at Server_IssuerJwks, return that file if so;
// otherwise, generate and store a private key at IssuerKey and return a public key of
// that private key, encapsulated in the JWKS format
//
// The private key generated is loaded to issuerPrivateJWK variable which is used for
// this server to sign JWTs it issues. The public key returned will be exposed publicly
// for other servers to verify JWTs signed by this server, typically via a well-known URL
// i.e. "/.well-known/issuer.jwks"
func GetIssuerPublicJWKS() (jwk.Set, error) {
	existingJWKS := param.Server_IssuerJwks.GetString()
	issuerKeysDir := param.IssuerKeysDirectory.GetString()
	return loadIssuerPublicJWKS(existingJWKS, issuerKeysDir)
}

// Check if there is a session secret exists at param.Server_SessionSecretFile and is not empty if there is one.
// If not, generate the secret to encrypt/decrypt session cookie
func GenerateSessionSecret() error {
	secretLocation := param.Server_SessionSecretFile.GetString()

	if secretLocation == "" {
		return errors.New("Empty filename for Server_SessionSecretFile")
	}

	user, err := GetPelicanUser()
	if err != nil {
		return err
	}

	// First open the file and see if there is a secret in it already
	if file, err := os.Open(secretLocation); err == nil {
		defer file.Close()
		existingSecretBytes := make([]byte, 1024)
		_, err := file.Read(existingSecretBytes)
		if err != nil {
			return errors.Wrap(err, "Failed to read existing session secret file")
		}
		if len(string(existingSecretBytes)) == 0 {
			return errors.Wrap(err, "Empty session secret file")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(err, "Failed to load session secret due to I/O error")
	}
	keyDir := filepath.Dir(secretLocation)
	if err := MkdirAll(keyDir, 0750, user.Uid, user.Gid); err != nil {
		return err
	}

	// In this case, the session secret file doesn't exist.
	file, err := os.OpenFile(secretLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return errors.Wrap(err, fmt.Sprint("Failed to create new session secret file at ", secretLocation))
	}
	defer file.Close()
	// Windows does not have "chown", has to work differently
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		cmd := exec.Command("icacls", secretLocation, "/grant", user.Username+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated session secret %v to daemon group %v: %s",
				secretLocation, user.Groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(secretLocation, user.Uid, user.Gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated session secret %v to daemon group %v",
				secretLocation, user.Groupname)
		}
	}

	secret, err := GetSecret()
	if err != nil {
		return errors.Wrap(err, "failed to get the secret")
	}

	_, err = file.WriteString(secret)

	if err != nil {
		return errors.Wrap(err, "")
	}
	return nil
}

// Load session secret from Server_SessionSecretFile. Generate session secret
// if no file present.
func LoadSessionSecret() ([]byte, error) {
	secretLocation := param.Server_SessionSecretFile.GetString()

	if secretLocation == "" {
		return []byte{}, errors.New("Empty filename for Server_SessionSecretFile")
	}

	if err := GenerateSessionSecret(); err != nil {
		return []byte{}, err
	}

	rest, err := os.ReadFile(secretLocation)
	if err != nil {
		return []byte{}, errors.Wrap(err, "Error reading secret file")
	}
	return rest, nil
}

// Check to see if two given maps of jwk.Keys are logically
// equivalent
func areKeysDifferent(a, b map[string]jwk.Key) bool {
	if len(a) != len(b) {
		return true
	}

	for key := range a {
		if _, exists := b[key]; !exists {
			return true
		}
	}

	for key := range b {
		if _, exists := a[key]; !exists {
			return true
		}
	}

	return false // All keys are the same
}

// Refresh the private keys directory and return `true` if the keys have changed
// since the last refresh
func RefreshKeys() (bool, error) {
	before := GetIssuerPrivateKeys()
	_, err := loadIssuerPrivateKey(param.IssuerKeysDirectory.GetString())
	if err != nil {
		return false, err
	}
	after := GetIssuerPrivateKeys()
	keysChanged := areKeysDifferent(before, after)

	log.Debugf("Private keys directory refreshed successfully")
	return keysChanged, nil
}
