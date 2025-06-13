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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/param"
)

func TestGetSecret(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})
	t.Run("generate-32B-hash", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		get, err := GetSecret()
		require.NoError(t, err)
		assert.Len(t, get, 32)
	})
}

func TestEncryptString(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})

	t.Run("encrypt-without-err", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		get, err := EncryptString("Some secret to encrypt")
		require.NoError(t, err)
		assert.NotEmpty(t, get)
	})
}

func TestDecryptString(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})
	t.Run("decrypt-without-err", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		secret := "Some secret to encrypt"

		getEncrypt, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, getEncrypt)

		getDecrypt, err := DecryptString(getEncrypt)
		require.NoError(t, err)
		assert.Equal(t, secret, getDecrypt)
	})

	t.Run("diff-secrets-yield-diff-result", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		secret := "Some secret to encrypt"

		getEncrypt, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, getEncrypt)

		ResetConfig()
		newKeyDir := filepath.Join(tmp, "new-issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), newKeyDir)

		getDecrypt, err := DecryptString(getEncrypt)
		require.NoError(t, err)
		assert.NotEqual(t, secret, getDecrypt)
	})
}

func TestKeyRotation(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})

	t.Run("new-key-updates-config", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		// Set empty password for testing
		setEmptyPassword = true

		// Create initial config
		config := OSDFConfig{}
		err := SaveConfigContents(&config)
		require.NoError(t, err)

		// Get the initial key ID
		initialKey, err := GetIssuerPrivateJWK()
		require.NoError(t, err)
		initialKeyID := initialKey.KeyID()
		t.Logf("initialKeyID: %s", initialKeyID)

		// Remove initial key
		err = os.RemoveAll(keyDir)
		require.NoError(t, err)

		// Create a new key ID and set it as the current key
		newKey, err := GeneratePEM(keyDir)
		require.NoError(t, err)
		newKeyID := newKey.KeyID()
		t.Logf("newKeyID: %s", newKeyID)

		newKeyDetected, err := RefreshKeys()
		require.NoError(t, err)
		require.True(t, newKeyDetected)

		// Verify the keys are different
		require.NotEqual(t, initialKeyID, newKeyID)

		// Read the config - this should trigger key update in the config
		readConfig, err := GetCredentialConfigContents()
		require.NoError(t, err)
		require.Equal(t, config, readConfig)

		// Verify the config was re-encrypted with the new key
		encContents, err := GetEncryptedContents()
		require.NoError(t, err)

		rest := []byte(encContents)
		var foundKeyID string
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "ENCRYPTED PRIVATE KEY" || block.Type == "PRIVATE KEY" {
				if kid, ok := block.Headers["KeyId"]; ok {
					foundKeyID = kid
				}
			}
			rest = remaining
		}

		require.NotEmpty(t, foundKeyID)
		require.Equal(t, newKeyID, foundKeyID)
	})

	t.Run("backward-compatibility", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), keyDir)

		currentKey, err := GetIssuerPrivateJWK()
		require.NoError(t, err)

		// Set empty password for testing
		setEmptyPassword = true

		// Encrypt the private key
		// Extract the underlying private key
		var rawKey interface{}
		err = currentKey.Raw(&rawKey)
		require.NoError(t, err)
		// Convert to ECDSA key
		ecdsaKey, ok := rawKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		// Convert private key to PKCS8 format
		key_bytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
		require.NoError(t, err)

		pem_block := pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: key_bytes,
		}
		pem_bytes_memory := append(pem.EncodeToMemory(&pem_block), '\n')

		// Encrypt the config
		// Create initial config without key ID (legacy config)
		config := OSDFConfig{}
		contents, err := yaml.Marshal(config)
		require.NoError(t, err)

		// Convert to X25519 for encryption
		x25519_sk := ConvertX25519Key(ecdsaKey.D.Bytes())
		x25519_pk_slice, err := curve25519.X25519(x25519_sk[:], curve25519.Basepoint)
		require.NoError(t, err)
		var x25519_pk [32]byte
		copy(x25519_pk[:], x25519_pk_slice)

		boxed_bytes, err := box.SealAnonymous(nil, []byte(contents), &x25519_pk, rand.Reader)
		require.NoError(t, err)
		pem_block.Type = "ENCRYPTED CONFIG"
		pem_block.Bytes = boxed_bytes
		pem_bytes_memory = append(pem_bytes_memory, pem.EncodeToMemory(&pem_block)...)

		// Bundle the encrypted private key and the encrypted config into a single PEM file
		err = SaveEncryptedContents(pem_bytes_memory)
		require.NoError(t, err)

		// Read the config - this should trigger key update in the config
		readConfig, err := GetCredentialConfigContents()
		require.NoError(t, err)
		require.Equal(t, config, readConfig)

		// Verify the config was re-encrypted with the new key
		encContents, err := GetEncryptedContents()
		require.NoError(t, err)

		rest := []byte(encContents)
		var foundKeyID string
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "ENCRYPTED CONFIG" {
				if kid, ok := block.Headers["KeyId"]; ok {
					foundKeyID = kid
				}
			}
			rest = remaining
		}

		require.NotEmpty(t, foundKeyID)
		require.Equal(t, currentKey.KeyID(), foundKeyID)
	})
}
