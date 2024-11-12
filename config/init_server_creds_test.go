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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encrypt should be ecdsa|rsa
// keyFormat should be pkcs1|pkcs8
func generatePrivateKey(keyLocation string, encrypt string, keyFormat string) error {
	file, err := os.OpenFile(keyLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return errors.Wrap(err, "Failed to create new private key file")
	}
	defer file.Close()
	if encrypt == "ecdsa" {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	} else if encrypt == "rsa" {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		if keyFormat == "pkcs8" {
			bytes, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				return err
			}
			priv_block := pem.Block{Type: "PRIVATE KEY", Bytes: bytes}
			if err = pem.Encode(file, &priv_block); err != nil {
				return err
			}
		} else if keyFormat == "pkcs1" {
			bytes := x509.MarshalPKCS1PrivateKey(priv)
			priv_block := pem.Block{Type: "RSA PRIVATE KEY", Bytes: bytes}
			if err = pem.Encode(file, &priv_block); err != nil {
				return err
			}
		} else {
			return errors.Errorf("unsupported key format: %s", keyFormat)
		}
	} else {
		return errors.Errorf("unsupported encrypt: %s", encrypt)
	}
	return nil
}

func TestLoadPrivateKey(t *testing.T) {
	t.Run("ecdsa-key", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "ecdsa.key")
		err := generatePrivateKey(keyLocation, "ecdsa", "pkcs8")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, false)
		require.NoError(t, err)
		require.NotNil(t, privateKey)

		if _, ok := privateKey.(*ecdsa.PrivateKey); !ok {
			assert.Fail(t, "loaded private key type is not *ecdsa.PrivateKey")
		}
	})

	t.Run("rsa-pkcs8-key-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs8")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, true)
		require.NoError(t, err)
		require.NotNil(t, privateKey)

		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			assert.Fail(t, "loaded private key type is not *rsa.PrivateKey")
		}
	})

	t.Run("rsa-pkcs1-key-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs1")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, true)
		require.NoError(t, err)
		require.NotNil(t, privateKey)

		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			assert.Fail(t, "loaded private key type is not *rsa.PrivateKey")
		}
	})

	t.Run("rsa-pkcs1-key-not-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs1")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RSA type private key is not allowed for")
		require.Nil(t, privateKey)
	})

	t.Run("rsa-pkcs8-key-not-allowed", func(t *testing.T) {
		tempDir := t.TempDir()
		keyLocation := filepath.Join(tempDir, "rsa.key")
		err := generatePrivateKey(keyLocation, "rsa", "pkcs8")
		require.NoError(t, err)
		privateKey, err := LoadPrivateKey(keyLocation, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RSA type private key in PKCS #8 form is not allowed for")
		require.Nil(t, privateKey)
	})
}

func TestLoadIssuerPrivateKey(t *testing.T) {
	tempDir := t.TempDir()
	issuerKeyDir := filepath.Join(tempDir, param.IssuerKey.GetString())

	key, err := loadIssuerPrivateKey(issuerKeyDir)
	require.NoError(t, err)
	require.NotNil(t, key)
}

// This test also imitates the origin API endpoint "/newIssuerKey"
func TestSecondPrivateKey(t *testing.T) {
	tempDir := t.TempDir()
	issuerKeyDir := filepath.Join(tempDir, param.IssuerKey.GetString())

	key, err := loadIssuerPrivateKey(issuerKeyDir)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Wait for 1 second to avoid duplicated private key filenames
	// because they are named after unix epoch timestamp
	time.Sleep(1 * time.Second)

	// Create another private key
	parentDir := filepath.Dir(issuerKeyDir)
	defaultPrivateKeysDir := filepath.Join(parentDir, "issuer-keys")
	secondKey, err := GeneratePEMandSetActiveKey(defaultPrivateKeysDir)
	require.NoError(t, err)
	require.NotNil(t, secondKey)
	assert.NotEqual(t, key.KeyID(), secondKey.KeyID())

	// Check if the active private key points to the lastest key
	latestKey, err := GetIssuerPrivateJWK()
	require.NoError(t, err)
	assert.Equal(t, secondKey.KeyID(), latestKey.KeyID())
}
