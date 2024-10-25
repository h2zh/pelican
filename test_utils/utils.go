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

package test_utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
)

func TestContext(ictx context.Context, t *testing.T) (ctx context.Context, cancel context.CancelFunc, egrp *errgroup.Group) {
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ictx, deadline)
	} else {
		ctx, cancel = context.WithCancel(ictx)
	}
	egrp, ctx = errgroup.WithContext(ctx)
	ctx = context.WithValue(ctx, config.EgrpKey, egrp)
	return
}

// Creates a buffer of at least 1MB
func makeBigBuffer() []byte {
	byteBuff := []byte("Hello, World!")
	for {
		byteBuff = append(byteBuff, []byte("Hello, World!")...)
		if len(byteBuff) > 1024*1024 {
			break
		}
	}
	return byteBuff
}

// Writes a file at least the specified size in MB
func WriteBigBuffer(t *testing.T, fp io.WriteCloser, sizeMB int) (size int) {
	defer fp.Close()
	byteBuff := makeBigBuffer()
	size = 0
	for {
		n, err := fp.Write(byteBuff)
		require.NoError(t, err)
		size += n
		if size > sizeMB*1024*1024 {
			break
		}
	}
	return
}

// JWKSetToList converts a jwk.Set to a list of individual JWK keys
func JWKSetToList(set jwk.Set) ([]jwk.Key, error) {
	if set == nil {
		return nil, fmt.Errorf("jwk set is nil")
	}

	keys := make([]jwk.Key, 0, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			return nil, fmt.Errorf("index %d is out of bound of jwks", i)
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// GenerateJWK generates a JWK private key and a corresponding JWKS public key,
// and the string representation of the public key
func GenerateJWK() (jwk.Key, jwk.Set, string, error) {
	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a JWK from the private key
	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, "", err
	}
	_ = jwkKey.Set(jwk.KeyIDKey, "mykey")
	_ = jwkKey.Set(jwk.AlgorithmKey, "RS256")
	_ = jwkKey.Set(jwk.KeyUsageKey, "sig")

	// Extract the public key
	publicKey, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a JWKS from the public key
	jwks := jwk.NewSet()
	if err := jwks.AddKey(publicKey); err != nil {
		return nil, nil, "", err
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, nil, "", err
	}

	return jwkKey, jwks, string(jwksBytes), nil
}

// GenerateMultipleJWK generates multiple JWK private keys and a corresponding JWKS containing all public keys,
// and returns the private keys, the JWKS, and the string representation of the JWKS
func GenerateMultipleJWK(count int) ([]jwk.Key, jwk.Set, string, error) {
	if count <= 0 {
		return nil, nil, "", fmt.Errorf("count must be greater than 0")
	}

	privateKeys := make([]jwk.Key, 0, count)

	// Create a JWKS for public keys
	jwks := jwk.NewSet()

	for i := 0; i < count; i++ {
		// Generate an RSA private key
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to generate RSA key %d: %w", i+1, err)
		}

		// Create a JWK from the private key
		jwkKey, err := jwk.FromRaw(privateKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to create JWK from private key %d: %w", i+1, err)
		}

		// Set key properties
		_ = jwkKey.Set(jwk.KeyIDKey, fmt.Sprintf("key%d", i+1))
		_ = jwkKey.Set(jwk.AlgorithmKey, "RS256")
		_ = jwkKey.Set(jwk.KeyUsageKey, "sig")

		// Store the private key
		privateKeys = append(privateKeys, jwkKey)

		// Extract the public key
		publicKey, err := jwk.PublicKeyOf(jwkKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to extract public key %d: %w", i+1, err)
		}

		// Add public key to JWKS
		if err := jwks.AddKey(publicKey); err != nil {
			return nil, nil, "", fmt.Errorf("failed to add public key %d to JWKS: %w", i+1, err)
		}
	}

	// Marshal JWKS to string
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	return privateKeys, jwks, string(jwksBytes), nil
}

func GenerateJWKS() (string, error) {
	// Create a private key to use for the test
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "Error generating private key")
	}

	// Convert from raw ecdsa to jwk.Key
	pKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to convert ecdsa.PrivateKey to jwk.Key")
	}

	//Assign Key id to the private key
	err = jwk.AssignKeyID(pKey)
	if err != nil {
		return "", errors.Wrap(err, "Error assigning kid to private key")
	}

	//Set an algorithm for the key
	err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
	if err != nil {
		return "", errors.Wrap(err, "Unable to set algorithm for pKey")
	}

	publicKey, err := pKey.PublicKey()
	if err != nil {
		return "", errors.Wrap(err, "Unable to get the public key from private key")
	}

	jwks := jwk.NewSet()
	err = jwks.AddKey(publicKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to add public key to the jwks")
	}

	jsonData, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return "", errors.Wrap(err, "Unable to marshal the json into string")
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')

	return string(jsonData), nil
}

// For these tests, we only need to lookup key locations. Create a dummy registry that only returns
// the jwks_uri location for the given key. Once a server is instantiated, it will only return
// locations for the provided prefix. To change prefixes, create a new registry mockup.
func RegistryMockup(t *testing.T, prefix string) *httptest.Server {
	registryUrl, _ := url.Parse("https://registry.com:8446")
	path, err := url.JoinPath("/api/v1.0/registry", prefix, ".well-known/issuer.jwks")
	if err != nil {
		t.Fatalf("Failed to parse key path for prefix %s", prefix)
	}
	registryUrl.Path = path

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse := `{"jwks_uri": "` + registryUrl.String() + `"}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonResponse))
	}))
	t.Cleanup(server.Close)
	return server
}

// Initialize the client for a unit test
//
// Will set the configuration to a temporary directory (to
// avoid pulling in global configuration) and set some arbitrary
// viper configurations
func InitClient(t *testing.T, initCfg map[string]any) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	viper.Set("ConfigDir", t.TempDir())
	for key, val := range initCfg {
		viper.Set(key, val)
	}

	config.InitConfig()
	require.NoError(t, config.InitClient())
}
