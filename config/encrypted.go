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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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
	configDir := viper.GetString("ConfigDir")
	if GetPreferredPrefix() == PelicanPrefix || IsRootExecution() {
		return filepath.Join(configDir, "credentials", "client-credentials.pem"), nil
	}
	configLocation := filepath.Join("osdf-client", "oauth2-client.pem")
	configRoot := os.Getenv("XDG_CONFIG_HOME")
	if len(configRoot) == 0 {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configRoot = filepath.Join(dirname, ".config")
	}
	return filepath.Join(configRoot, configLocation), nil
}

func EncryptedConfigExists() (bool, error) {
	filename, err := GetEncryptedConfigName()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// Return the PEM-formatted contents of the encrypted configuration file
func GetEncryptedContents() (string, error) {
	filename, err := GetEncryptedConfigName()
	if err != nil {
		return "", err
	}
	log.Debugln("Will read credential configuration from", filename)

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

			err = os.MkdirAll(filepath.Dir(filename), 0700)
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

	configDir := filepath.Dir(filename)
	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		return err
	}
	fp, err := os.CreateTemp(configDir, "oauth2-client.pem")
	if err != nil {
		return err
	}
	// Ensure that the file is closed before we attempt to rename it.
	// Otherwise, on Windows, the rename operation will fail.
	err = func() error {
		defer fp.Close()
		if _, err := fp.Write(encContents); err != nil {
			os.Remove(fp.Name())
			return err
		}
		if err := fp.Sync(); err != nil {
			os.Remove(fp.Name())
			return err
		}
		return nil
	}()
	if err != nil {
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
		fmt.Fprintln(os.Stderr, "Please provide a new password to encrypt the local OSDF client configuration file: ")
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

// Returns the current contents of the credential configuration
// from disk.
func GetCredentialConfigContents() (OSDFConfig, error) {
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
	var keyID string

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
			if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return config, err
			}
			foundKey = true
			// Extract the KeyId from the PEM headers of the encrypted private key block.
			// This ID identifies which issuer key was used to encrypt this configuration.
			if kid, ok := block.Headers["KeyId"]; ok {
				keyID = kid
			}
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

	// Convert to ECDSA key
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return config, errors.New("Config contents do not include an ECDSA private key")
	}

	// Convert to X25519 for decryption
	x25519_sk := ConvertX25519Key(ecdsaKey.D.Bytes())
	x25519_pk_slice, err := curve25519.X25519(x25519_sk[:], curve25519.Basepoint)
	if err != nil {
		return config, err
	}
	var x25519_pk [32]byte
	copy(x25519_pk[:], x25519_pk_slice)

	// Get the current key ID
	currentKey, err := GetIssuerPrivateJWK()
	if err != nil {
		return config, err
	}
	currentKeyID := currentKey.KeyID()

	// Re-encrypt to update the keyID header in the config when either:
	//   - the keyID header is missing (keyID == ""), or
	//   - the keyID header exists but doesn't match the current issuer key.
	needsUpdate := keyID == "" || keyID != currentKeyID
	if needsUpdate {
		if keyID == "" {
			log.Debugf("Updating encrypted client configuration that had no KeyId header to current key %s",
				currentKeyID)
		} else {
			log.Debugf("Updating encrypted client configuration from key %s to current key %s",
				keyID, currentKeyID)
		}
		// Re-encrypt the config with the current key
		if err := SaveConfigContents(&config); err != nil {
			return config, err
		}
	}

	messages, ok := box.OpenAnonymous(nil, data, &x25519_pk, &x25519_sk)
	if !ok {
		return config, errors.New("Failed to open secret box containing config")
	}

	err = yaml.Unmarshal(messages, &config)
	return config, err
}

func ResetPassword() error {
	input_config, err := GetCredentialConfigContents()
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

	// Get the current issuer key to encrypt the config
	currentKey, err := GetIssuerPrivateJWK()
	if err != nil {
		return err
	}

	// Extract the underlying private key
	var rawKey interface{}
	if err := currentKey.Raw(&rawKey); err != nil {
		return err
	}

	// Convert to ECDSA key
	ecdsaKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("Issuer key is not an ECDSA key")
	}

	// Convert private key to PKCS8 format
	key_bytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		return err
	}

	// Save as PEM with the key ID in headers
	keyPEM := pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: key_bytes,
		Headers: map[string]string{
			"KeyId": currentKey.KeyID(),
		},
	}

	// Convert to X25519 for encryption
	x25519_sk := ConvertX25519Key(ecdsaKey.D.Bytes())
	x25519_pk_slice, err := curve25519.X25519(x25519_sk[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	var x25519_pk [32]byte
	copy(x25519_pk[:], x25519_pk_slice)

	// Encrypt the config
	boxed_bytes, err := box.SealAnonymous(nil, []byte(contents), &x25519_pk, rand.Reader)
	if err != nil {
		return errors.New("Failed to seal config")
	}

	configPEM := pem.Block{
		Type:  "ENCRYPTED CONFIG",
		Bytes: boxed_bytes,
		Headers: map[string]string{
			"KeyId": currentKey.KeyID(),
		},
	}

	// Combine both PEM blocks
	pemBytesMemory := append(pem.EncodeToMemory(&keyPEM), '\n')
	pemBytesMemory = append(pemBytesMemory, pem.EncodeToMemory(&configPEM)...)

	return SaveEncryptedContents(pemBytesMemory)
}

// Get a 32B secret from server IssuerKey
//
// How we generate the secret:
// Concatenate the byte array pelican with the DER form of the service's private key,
// Take a hash, and use the hash's bytes as the secret.
func GetSecret() (string, error) {
	// Use issuer private key as the source to generate the secret
	privateKey, err := GetIssuerPrivateJWK()
	if err != nil {
		return "", err
	}

	// Extract the underlying ECDSA private key in native Go crypto key type
	var rawKey interface{}
	if err := privateKey.Raw(&rawKey); err != nil {
		return "", err
	}

	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(rawKey)

	if err != nil {
		return "", err
	}
	byteArray := []byte("pelican")

	concatenated := append(byteArray, derPrivateKey...)

	hash := sha256.Sum256(concatenated)

	secret := string(hash[:])
	return secret, nil
}

// Encrypt function
func EncryptString(stringToEncrypt string) (encryptedString string, err error) {
	secret, err := GetSecret()
	if err != nil {
		return "", err
	}
	key := []byte(secret)
	plaintext := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt function
func DecryptString(encryptedString string) (decryptedString string, err error) {
	secret, err := GetSecret()
	if err != nil {
		return "", err
	}
	key := []byte(secret)

	ciphertext, _ := base64.URLEncoding.DecodeString(encryptedString)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
