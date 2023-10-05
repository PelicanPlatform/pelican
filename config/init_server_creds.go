/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	privateKey atomic.Pointer[jwk.Key]
)

func LoadPrivateKey(tlsKey string) (*ecdsa.PrivateKey, error) {
	rest, err := os.ReadFile(tlsKey)
	if err != nil {
		return nil, nil
	}

	var privateKey *ecdsa.PrivateKey
	var block *pem.Block
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
			default:
				return nil, fmt.Errorf("Unsupported private key type: %T", key)
			}
			break
		}
	}
	if privateKey == nil {
		return nil, fmt.Errorf("Private key file, %v, contains no private key", tlsKey)
	}
	return privateKey, nil
}

func LoadPublicKey(existingJWKS string, issuerKeyFile string) (*jwk.Set, error) {
	jwks := jwk.NewSet()
	if existingJWKS != "" {
		var err error
		jwks, err = jwk.ReadFile(existingJWKS)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read issuer JWKS file")
		}
	}

	if err := GeneratePrivateKey(issuerKeyFile, elliptic.P256()); err != nil {
		return nil, errors.Wrap(err, "Failed to generate new private key")
	}
	contents, err := os.ReadFile(issuerKeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read issuer key file")
	}
	key, err := jwk.ParseKey(contents, jwk.WithPEM(true))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse issuer key file %v", issuerKeyFile)
	}

	// Add the algorithm to the key, needed for verifying tokens elsewhere
	err = key.Set(jwk.AlgorithmKey, jwa.ES256)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to add alg specification to key header")
	}

	pkey, err := jwk.PublicKeyOf(key)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to generate public key from file %v", issuerKeyFile)
	}
	err = jwk.AssignKeyID(pkey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to assign key ID to public key")
	}
	if err = jwks.AddKey(pkey); err != nil {
		return nil, errors.Wrap(err, "Failed to add public key to new JWKS")
	}
	return &jwks, nil
}

func GenerateCACert() error {
	gid, err := GetDaemonGID()
	if err != nil {
		return err
	}
	groupname, err := GetDaemonGroup()
	if err != nil {
		return err
	}

	tlsCert := viper.GetString("TLSCACertFile")
	if file, err := os.Open(tlsCert); err == nil {
		file.Close()
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	certDir := filepath.Dir(tlsCert)
	if err := MkdirAll(certDir, 0755, -1, gid); err != nil {
		return err
	}

	tlsKey := viper.GetString("TLSCAKey")
	if err := GeneratePrivateKey(tlsKey, elliptic.P256()); err != nil {
		return err
	}
	privateKey, err := LoadPrivateKey(tlsKey)
	if err != nil {
		return err
	}

	log.Debugln("Will generate a new CA certificate for the server")
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
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
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &(privateKey.PublicKey),
		privateKey)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(tlsCert, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = os.Chown(tlsCert, -1, gid); err != nil {
		return errors.Wrapf(err, "Failed to chown generated certificate %v to daemon group %v",
			tlsCert, groupname)
	}

	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return nil
}

func LoadCertficate(certFile string) (*x509.Certificate, error) {
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
		return nil, fmt.Errorf("Certificate file, %v, contains no certificate", certFile)
	}
	return cert, nil
}

func GenerateCert() error {
	gid, err := GetDaemonGID()
	if err != nil {
		return err
	}
	groupname, err := GetDaemonGroup()
	if err != nil {
		return err
	}

	tlsCert := param.TLSCertificate.GetString()
	if file, err := os.Open(tlsCert); err == nil {
		file.Close()
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// In this case, no host certificate exists - we should generate our own.
	if err := GenerateCACert(); err != nil {
		return err
	}
	caCert, err := LoadCertficate(viper.GetString("TLSCACertFile"))
	if err != nil {
		return err
	}

	certDir := filepath.Dir(tlsCert)
	if err := MkdirAll(certDir, 0755, -1, gid); err != nil {
		return err
	}

	tlsKey := param.TLSKey.GetString()
	privateKey, err := LoadPrivateKey(tlsKey)
	if err != nil {
		return err
	}

	// Note: LoadPrivateKey will return nil for the private key if the file
	// doesn't exist.  In that case, we'll do a self-signed certificate
	caPrivateKey, err := LoadPrivateKey(viper.GetString("TLSCAKey"))
	if err != nil {
		return err
	}

	log.Debugln("Will generate a new host certificate for the server")
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
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
	if signingKey == nil {
		signingCert = &template
		signingKey = privateKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, signingCert, &(privateKey.PublicKey),
		signingKey)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(tlsCert, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = os.Chown(tlsCert, -1, gid); err != nil {
		return errors.Wrapf(err, "Failed to chown generated certificate %v to daemon group %v",
			tlsCert, groupname)
	}

	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return nil
}

func GeneratePrivateKey(keyLocation string, curve elliptic.Curve) error {
	gid, err := GetDaemonGID()
	if err != nil {
		return err
	}
	user, err := GetDaemonUser()
	if err != nil {
		return err
	}
	groupname, err := GetDaemonGroup()
	if err != nil {
		return err
	}

	if file, err := os.Open(keyLocation); err == nil {
		file.Close()
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(err, "Failed to load private key due to I/O error")
	}
	keyDir := filepath.Dir(keyLocation)
	if err := MkdirAll(keyDir, 0750, -1, gid); err != nil {
		return err
	}
	// In this case, the private key file doesn't exist.
	file, err := os.OpenFile(keyLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return errors.Wrap(err, "Failed to create new private key file")
	}
	defer file.Close()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	// Windows does not have "chown", has to work differently
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		cmd := exec.Command("icacls", keyLocation, "/grant", user+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v: %s",
				keyLocation, groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(keyLocation, uid, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
				keyLocation, groupname)
		}
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

func GenerateIssuerJWKS() (*jwk.Set, error) {
	existingJWKS := viper.GetString("IssuerJWKS")
	issuerKeyFile := param.IssuerKey.GetString()
	return LoadPublicKey(existingJWKS, issuerKeyFile)
}

func GetOriginJWK() (*jwk.Key, error) {
	key := privateKey.Load()
	if key == nil {
		issuerKeyFile := param.IssuerKey.GetString()
		contents, err := os.ReadFile(issuerKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read key file")
		}
		newKey, err := jwk.ParseKey(contents, jwk.WithPEM(true))
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to parse key file")
		}
		privateKey.Store(&newKey)
		key = &newKey
	}
	return key, nil
}
