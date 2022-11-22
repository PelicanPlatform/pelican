package config

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"os"

	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

func GetEncryptedConfigName() (string, error) {
	config_dir := os.Getenv("XDG_CONFIG_HOME")
	if len(config_dir) > 0 {
		return path.Join(config_dir, "osdf-client", "oauth2-client.pem"), nil
	}
	dirname, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return path.Join(dirname, ".config", "osdf-client", "oauth2-client.pem"), nil
}

func GetEncryptedContents() (string, error) {
	filename, err := GetEncryptedConfigName()
	if err != nil {
		return "", err
	}
	
	buf, err := os.ReadFile(filename)
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			os.MkdirAll(path.Dir(filename), 0700)
			if fp, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				defer fp.Close()
			}
			return "", nil
		}
		return "", err
	}
	return string(buf), nil
}

func SaveEncryptedContents(encContents []byte) (error) {
	filename, err := GetEncryptedConfigName()
	if err != nil {
		return err
	}

	configDir := path.Dir(filename)
	os.MkdirAll(configDir, 0700)
	fp, err := os.CreateTemp(configDir, "oauth2-client.pem")
	if err != nil {
		return err
	}
	defer fp.Close()
	if _, err := fp.Write(encContents); err != nil {
		os.Remove(fp.Name())
		return err
	}
	if err := fp.Sync(); err != nil {
		os.Remove(fp.Name())
		return err
	}

	if err := os.Rename(fp.Name(), filename); err != nil {
		os.Remove(fp.Name())
		return err
	}
	return nil
}

func ConvertX25519Key(ed25519_sk []byte) ([32]byte) {
	hashed_sk := sha512.Sum512(ed25519_sk)
	hashed_sk[0] &= 248
	hashed_sk[31] &= 127
	hashed_sk[31] |= 64
	var result [32]byte
	copy(result[:], hashed_sk[:])
	return result
}

func GetPassword() ([]byte, error) {
	if fileInfo, _ := os.Stdin.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		return nil, errors.New("Cannot read password; not connected to a terminal")
	}
	fmt.Fprint(os.Stderr, "Enter password for OSDF client configuration: ")

	stdin := int(os.Stdin.Fd())

	oldState, err := term.MakeRaw(stdin)
	if err != nil {
		return nil, err
	}
	defer fmt.Fprintf(os.Stderr, "\n")
	defer term.Restore(stdin, oldState)
	return term.ReadPassword(stdin)
}

func GetConfigContents() (OSDFConfig, error) {
	config := OSDFConfig{}

	encContents, err := GetEncryptedContents()
	if len(encContents) == 0 {
		return config, nil
	}
	if err != nil {
		return config, err
	}

	foundKey := false
	foundData := false
	rest := []byte(encContents)
	var data []byte
	var key interface{}
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "PRIVATE KEY" {
			if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return config, err
			}
			foundKey = true
		} else if block.Type == "ENCRYPTED PRIVATE KEY" {
			password, _ := TryGetPassword()
			typedPassword := false
			if len(password) == 0 {
				password, err = GetPassword()
				typedPassword = true
			}
			if err != nil {
				return config, err
			}
			if len(password) == 0 {
				return config, errors.New("Encrypted key present; must have non-empty password")
			}
			if key, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, password); err != nil {
				return config, err
			}
			if typedPassword {
				if err := SavePassword(password); err != nil {
					fmt.Fprintln(os.Stderr, "Failed to save password:", err)
				}
			}
			foundKey = true
		} else if block.Type == "ENCRYPTED CONFIG" {
			data = block.Bytes
			foundData = true
		}
	}
	if !foundKey {
		return config, errors.New("Encrypted config did not include key")
	} else if !foundData {
		return config, errors.New("Encrypted config did not include data block")
	}

	ed25519_sk, ok := key.(ed25519.PrivateKey)
	if !ok {
		return config, errors.New("Config contents do not include an ED25519 private key")
	}
	x25519_sk := ConvertX25519Key(ed25519_sk)
	x25519_pk_slice, err := curve25519.X25519(x25519_sk[:], curve25519.Basepoint)
	var x25519_pk [32]byte
	copy(x25519_pk[:], x25519_pk_slice)

	if err != nil {
		return config, err
	}

	messages, ok := box.OpenAnonymous(nil, data, &x25519_pk, &x25519_sk)
	if !ok {
		return config, errors.New("Failed to open secret box containing config")
	}

	err = yaml.Unmarshal(messages, &config)
	return config, err
}

func ResetPassword() error {
	input_config, err := GetConfigContents()
	if err != nil {
		return err
	}
	err = SaveConfigContents_internal(&input_config, true)
	if err != nil {
		return err
	}
	return nil
}

func SaveConfigContents(config *OSDFConfig) error {
	return SaveConfigContents_internal(config, false)
}

func SaveConfigContents_internal(config *OSDFConfig, forcePassword bool) error {
	defaultConfig := OSDFConfig{}
	if config == nil {
		config = &defaultConfig
	}

	contents, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	password, err := TryGetPassword()
	if forcePassword || len(password) == 0 || err != nil {
		password, err = GetPassword()
		if err != nil {
			return err
		}
	}

	_, ed25519_sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	x25519_sk := ConvertX25519Key(ed25519_sk)
	x25519_pk_slice, err := curve25519.X25519(x25519_sk[:], curve25519.Basepoint)
	var x25519_pk [32]byte
	copy(x25519_pk[:], x25519_pk_slice)

	boxed_bytes, err := box.SealAnonymous(nil, []byte(contents), &x25519_pk, rand.Reader)
	if err != nil {
		return errors.New("Failed to seal config")
	}

	var key_bytes []byte
	if len(password) == 0 {
		key_bytes, err = x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(ed25519_sk[:]))
	} else {
		opts := *pkcs8.DefaultOpts
		if kdfopts, ok := (opts.KDFOpts).(*pkcs8.PBKDF2Opts); ok {
			kdfopts.IterationCount = 100000
		}
		key_bytes, err = pkcs8.MarshalPrivateKey(ed25519.PrivateKey(ed25519_sk[:]), password, &opts)
	}
	if err != nil {
		return err
	}

	pem_block := pem.Block{Type:"ENCRYPTED PRIVATE KEY", Bytes:key_bytes}
	if len(password) == 0 {
		pem_block.Type = "PRIVATE KEY"
	}
	pem_bytes_memory := append(pem.EncodeToMemory(&pem_block), '\n')

	pem_block.Type = "ENCRYPTED CONFIG"
	pem_block.Bytes = boxed_bytes

	pem_bytes_memory = append(pem_bytes_memory, pem.EncodeToMemory(&pem_block)...)

	if len(password) > 0 {
		err = SavePassword(password)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to save password to session keychain:", err)
		}
	}

	return SaveEncryptedContents(pem_bytes_memory)
}
