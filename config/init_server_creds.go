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
	"path/filepath"
	"os"
	"sync/atomic"
	"time"
	"encoding/json"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var (
	privateKey atomic.Pointer[jwk.Key]
)

func LoadPrivateKey(tlsKey string)(*ecdsa.PrivateKey, error) {
	fmt.Println("new load Private Key")
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
	
	if err := GeneratePrivateKey(issuerKeyFile); err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(issuerKeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read issuer key file")
	}
	key, err := jwk.ParseKey(contents, jwk.WithPEM(true))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse issuer key file %v", issuerKeyFile)
	}
	pkey, err := jwk.PublicKeyOf(key)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to generate public key from file %v", issuerKeyFile)
	}
	err = jwk.AssignKeyID(pkey)
	if err != nil {
		return nil, err
	}
	jwks.Add(pkey)
	return &jwks, nil
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

	tlsCert := viper.GetString("TLSCertificate")
	if file, err := os.Open(tlsCert); err == nil {
		file.Close()
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	certDir := filepath.Dir(tlsCert)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	tlsKey := viper.GetString("TLSKey")
	privateKey, err := LoadPrivateKey(tlsKey)
	if err != nil {
		return err
	}

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
			CommonName: hostname,
		},
		NotBefore: notBefore,
		NotAfter: notBefore.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
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

func GeneratePrivateKey(keyLocation string, curve elliptic.Curve) error {
	gid, err := GetDaemonGID()
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
		return err
	}
	keyDir := filepath.Dir(keyLocation)
	if err := os.MkdirAll(keyDir, 0750); err != nil {
		return err
	}
	// In this case, the private key file doesn't exist.
	file, err := os.OpenFile(keyLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	if err = os.Chown(keyLocation, -1, gid); err != nil {
		return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
			keyLocation, groupname)
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
	issuerKeyFile := viper.GetString("IssuerKey")
	return LoadPublicKey(existingJWKS, issuerKeyFile)
}

func GetOriginJWK() (*jwk.Key, error) {
	key := privateKey.Load()
	if key == nil {
		issuerKeyFile := viper.GetString("IssuerKey")
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

func JWKSMap(jwks *jwk.Set) (map[string]string, error) {
    // Marshal the set into JSON
    jsonBytes, err := json.MarshalIndent(jwks, "", "  ")
    if err != nil {
        return nil, err
    }

    // Parse the JSON into a structure we can manipulate
    var parsed map[string][]map[string]interface{}
    err = json.Unmarshal(jsonBytes, &parsed)
    if err != nil {
        return nil, err
    }

    // Convert the map[string]interface{} to map[string]string
    stringMaps := make([]map[string]string, len(parsed["keys"]))
    for i, m := range parsed["keys"] {
        stringMap := make(map[string]string)
        for k, v := range m {
            stringMap[k] = fmt.Sprintf("%v", v)
        }
        stringMaps[i] = stringMap
    }

    return stringMaps[0], nil
}