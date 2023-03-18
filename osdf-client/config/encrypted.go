package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// If we prompted the user for a new password while setting up the file,
// this global flag will be set to true.  This prevents us from asking for
// the password again later.
var setEmptyPassword = false

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

func EncryptedConfigExists() (bool, error) {
	filename, err := GetEncryptedConfigName()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil;
	} else if err != nil {
		return false, err;
	}
	return true, nil;
}

func GetEncryptedContents() (string, error) {
	filename, err := GetEncryptedConfigName()
	if err != nil {
		return "", err
	}

	buf, err := os.ReadFile(filename)
	if err != nil {
		if _, ok := err.(*os.PathError); ok {

			password, err := GetPassword(true)
			if err != nil {
				return "", err
			}
			if len(password) > 0 {
				if err := SavePassword(password); err != nil {
					fmt.Fprintln(os.Stderr, "Failed to save password:", err)
				}
			} else {
				setEmptyPassword = true
			}

			err = os.MkdirAll(path.Dir(filename), 0700)
			if err != nil {
				return "", err
			}
			if fp, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				defer fp.Close()
			}
			return "", nil
		}
		return "", err
	}
	return string(buf), nil
}

func SaveEncryptedContents(encContents []byte) error {
	filename, err := GetEncryptedConfigName()
	if err != nil {
		return err
	}

	configDir := path.Dir(filename)
	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		return err
	}
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

func ConvertX25519Key(ed25519_sk []byte) [32]byte {
	hashed_sk := sha512.Sum512(ed25519_sk)
	hashed_sk[0] &= 248
	hashed_sk[31] &= 127
	hashed_sk[31] |= 64
	var result [32]byte
	copy(result[:], hashed_sk[:])
	return result
}

func GetPassword(newFile bool) ([]byte, error) {
	if fileInfo, _ := os.Stdin.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		return nil, errors.New("Cannot read password; not connected to a terminal")
	}
	if newFile {
		fmt.Fprintln(os.Stderr, "The client is able to save the authorization in a local file.")
		fmt.Fprintln(os.Stderr, "This prevents the need to reinitialize the authorization for each transfer.")
		fmt.Fprintln(os.Stderr, "You will be asked for this password whenever a new session is started.")
		fmt.Fprintln(os.Stderr, "Please provide a new password to encrypt the local OSDF client configuration file: ");
	} else {
		fmt.Fprintln(os.Stderr, "The OSDF client configuration is encrypted.  Enter your password for the local OSDF client configuration file: ")
	}

	stdin := int(os.Stdin.Fd())

	oldState, err := term.MakeRaw(stdin)
	if err != nil {
		return nil, err
	}
	defer fmt.Fprintf(os.Stderr, "\n")
	defer func(fd int, oldState *term.State) {
		err := term.Restore(fd, oldState)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error restoring terminal state: %v\n", err)
		}
	}(stdin, oldState)
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
			// If the private key exists and is unprotected, assume this is
			// the same as the user explicitly setting an empty password.
			setEmptyPassword = true
		} else if block.Type == "ENCRYPTED PRIVATE KEY" {
			password, _ := TryGetPassword()
			typedPassword := false
			if len(password) == 0 {
				password, err = GetPassword(false)
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
	if setEmptyPassword {
		fmt.Fprintln(os.Stderr, "WARNING: empty password provided; the credentials will be saved unencrypted on disk")
	} else if forcePassword || len(password) == 0 || err != nil {
		var exists bool;
		if exists, err = EncryptedConfigExists(); err == nil && !exists {
			password, err = GetPassword(true)
		} else {
			password, err = GetPassword(false)
		}
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
	if err != nil {
		return err
	}
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

	pem_block := pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: key_bytes}
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
