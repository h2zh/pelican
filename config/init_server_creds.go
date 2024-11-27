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
	"github.com/pelicanplatform/pelican/utils"
)

var (
	// This is the private JWK for the server to sign tokens. This key remains
	// the same if the IssuerKey is unchanged
	issuerPrivateJWK atomic.Pointer[jwk.Key]

	// Representing private keys (from all .pem files) in the directory cache
	issuerPrivateKeys atomic.Pointer[map[string]jwk.Key]

	// Record the value of "IssuerKeysDirectory" param in case it changes during runtime
	currentIssuerKeysDir atomic.Value

	// Used to ensure initialization func init() is only called once
	initOnce sync.Once
)

// Reset the atomic pointer to issuer private jwk
func ResetIssuerJWKPtr() {
	issuerPrivateJWK.Store(nil)
}

// Set a private key as the active private key in use
func SetActiveKey(key jwk.Key) {
	issuerPrivateJWK.Store(&key)
}

// Clear all entries from the issuerPrivateKeys
func ResetIssuerPrivateKeys() {
	emptyMap := make(map[string]jwk.Key)
	issuerPrivateKeys.Store(&emptyMap)
}

// Safely load the current map and create a copy for modification
func getIssuerPrivateKeysCopy() map[string]jwk.Key {
	currentKeys := issuerPrivateKeys.Load()
	newMap := make(map[string]jwk.Key)
	if currentKeys != nil {
		for k, v := range *currentKeys {
			newMap[k] = v
		}
	}
	return newMap
}

// Read the current map
func GetIssuerPrivateKeys() map[string]jwk.Key {
	keysPtr := issuerPrivateKeys.Load()
	return *keysPtr
}

func getCurrentIssuerKeysDir() string {
	if val := currentIssuerKeysDir.Load(); val != nil {
		return val.(string)
	}
	return ""
}

func setCurrentIssuerKeysDir(dir string) {
	currentIssuerKeysDir.Store(dir)
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
	uid, err := GetDaemonUID()
	if err != nil {
		return err
	}

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
	if err := MkdirAll(keyDir, 0750, -1, gid); err != nil {
		return err
	}
	// In this case, the private key file doesn't exist.
	file, err := os.OpenFile(keyLocation, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return errors.Wrap(err, "Failed to create new private key file at "+keyLocation)
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

// Helper function to generate a Certificate Authority (CA) certificate and its private key
// for non-production environment so that we can use the private key of the CA
// to sign the host certificate
func GenerateCACert() error {
	gid, err := GetDaemonGID()
	if err != nil {
		return err
	}
	groupname, err := GetDaemonGroup()
	if err != nil {
		return err
	}
	user, err := GetDaemonUser()
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
	if err := MkdirAll(tlsCertDir, 0755, -1, gid); err != nil {
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
		cmd := exec.Command("icacls", tlsCACert, "/grant", user+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v: %s",
				tlsCACert, groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(tlsCACert, -1, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
				tlsCACert, groupname)
		}
	}

	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return nil
}

// Read a PEM-encoded TLS certficate file, parse and return the first
// certificate appeared in the chain. Return error if there's no cert
// present in the file
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

// Generate a TLS certificate (host certificate) and its private key
// for non-production environment if the requied TLS files are not present
func GenerateCert() error {
	gid, err := GetDaemonGID()
	if err != nil {
		return err
	}
	groupname, err := GetDaemonGroup()
	if err != nil {
		return err
	}
	user, err := GetDaemonUser()
	if err != nil {
		return err
	}

	tlsCertPrivateKeyExists := false

	tlsCert := param.Server_TLSCertificate.GetString()
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
				if _, err := LoadCertficate(caCert); err != nil {
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
	caCert, err := LoadCertficate(param.Server_TLSCACertificateFile.GetString())
	if err != nil {
		return err
	}

	// However, if only CA is missing but TLS cert and private key are present, we simply
	// generate the CA and return
	if tlsCertPrivateKeyExists {
		log.Debug("TLS Certficiate and its private key are present. Generated a CA and returns.")
		return nil
	}

	tlsCertDir := filepath.Dir(tlsCert)
	if err := MkdirAll(tlsCertDir, 0755, -1, gid); err != nil {
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

	log.Debugln("Server.TLSCertificate and/or Server.TLSKey do not exist. Will generate a new host certificate and its private key for the server")
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
		cmd := exec.Command("icacls", tlsCert, "/grant", user+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v: %s",
				tlsCert, groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(tlsCert, -1, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated key %v to daemon group %v",
				tlsCert, groupname)
		}
	}

	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	return nil
}

// Helper function to move the existing single key file to new directory
func migratePrivateKey(newDir string) error {
	legacyPrivateKeyFile := param.IssuerKey.GetString()
	if _, err := os.Stat(legacyPrivateKeyFile); os.IsNotExist(err) {
		return nil // No existing key exists
	}

	// Create the destination directory if it doesn't exist
	if err := os.MkdirAll(newDir, 0750); err != nil {
		return errors.Wrapf(err, "failed to create destination directory %s", newDir)
	}

	// Get the key id of the existing key
	key, err := loadSinglePEM(legacyPrivateKeyFile)
	if err != nil {
		log.Warnf("Failed to load key %s: %v", key.KeyID(), err)
		return err
	}

	// Rename the existing private key file and set destination path
	fileName := "migrated_key.pem"
	destPath := filepath.Join(newDir, fileName)

	// Check if a file with the same name already exists in the destination
	if _, err := os.Stat(destPath); err == nil {
		return errors.Errorf("destination file already exists: %s", destPath)
	}

	// Move the file
	if err := os.Rename(legacyPrivateKeyFile, destPath); err != nil {
		return errors.Wrapf(err, "failed to move %s to %s", legacyPrivateKeyFile, destPath)
	}

	return nil
}

// Helper function to initialize the in-memory map to save all private keys and migrate existing private key file
func initKeysMap(privateKeysDir string) error {
	initialMap := make(map[string]jwk.Key)
	issuerPrivateKeys.Store(&initialMap)
	setCurrentIssuerKeysDir(privateKeysDir)

	migrateErr := migratePrivateKey(privateKeysDir)
	if migrateErr != nil {
		return errors.Wrap(migrateErr, "failed to migrate existing private key file")
	}
	return nil
}

// Helper function to load one .pem file from specified filename
func loadSinglePEM(path string) (jwk.Key, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read key file")
	}

	key, err := jwk.ParseKey(contents, jwk.WithPEM(true))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse key")
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

// Helper function to load/refresh all .pem files from specified directory and find the most recent modified private key
func loadPEMFiles(dir string) (jwk.Key, error) {
	var mostRecentKey jwk.Key
	var mostRecentModTime time.Time

	files, err := os.ReadDir(dir)
	if err != nil {
		// It's fine if error is "directory not found". We'll create this dir using GeneratePEM func
		if os.IsNotExist(err) {
			newKey, err := GeneratePEMandSetActiveKey(dir)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create a new .pem file to save private key")
			}
			return newKey, nil
		}
		return nil, errors.Wrap(err, "failed to read directory that stores private keys")
	}

	latestKeys := getIssuerPrivateKeysCopy()
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".pem" {
			continue
		}
		// parse the private key in this file and add to the in-memory keys map
		keyPath := filepath.Join(dir, file.Name())
		key, err := loadSinglePEM(keyPath)
		if err != nil {
			log.Warnf("Failed to load key %s: %v", keyPath, err)
			continue
		}
		latestKeys[key.KeyID()] = key

		// find the most recent modified file
		fileInfo, err := file.Info()
		if err != nil {
			continue
		}
		if fileInfo.ModTime().After(mostRecentModTime) {
			mostRecentModTime = fileInfo.ModTime()
			mostRecentKey = key
		}
	}
	// The directory exists but contains no .pem files
	if len(latestKeys) == 0 {
		newKey, err := GeneratePEMandSetActiveKey(dir)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a new .pem file to save private key")
		}
		return newKey, nil
	}

	// Save up-to-date private keys and the active key in memory
	issuerPrivateKeys.Store(&latestKeys)
	SetActiveKey(mostRecentKey)
	log.Debugf("Set private key %s as active", mostRecentKey.KeyID())

	return mostRecentKey, nil
}

// Create a new .pem file and add its key to issuerPrivateKeys
// In other words, it combines GeneratePrivateKey and LoadPrivateKey functions
func GeneratePEM(dir string) (jwk.Key, error) {
	filename := fmt.Sprintf("pelican_generated_%d_%s.pem",
		time.Now().UnixNano(),
		utils.CreateRandomString(4))

	keyPath := filepath.Join(dir, filename)
	if err := GeneratePrivateKey(keyPath, elliptic.P256(), false); err != nil {
		return nil, errors.Wrap(err, "failed to generate new private key")
	}

	key, err := loadSinglePEM(keyPath)
	if err != nil {
		log.Warnf("Failed to load key %s: %v", keyPath, err)
	}

	// Save this new key in the in-memory map for all private keys
	keysCopy := getIssuerPrivateKeysCopy()
	keysCopy[key.KeyID()] = key
	issuerPrivateKeys.Store(&keysCopy)

	log.Debugf("Loaded the private key (key id: %s) into issuerPrivateKeys and set as active key", key.KeyID())
	return key, nil
}

// Generate a new .pem file and then set the private key it contains as the active one
// This function is also used in origin API to let admin generate new private key
func GeneratePEMandSetActiveKey(dir string) (jwk.Key, error) {
	newKey, err := GeneratePEM(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create a new .pem file to save private key")
	}
	SetActiveKey(newKey)
	return newKey, nil
}

// Re-scan the disk to load the issuer/server's private keys, return the active key to sign tokens it issues
func LoadIssuerPrivateKey(issuerKeysDir string) (jwk.Key, error) {
	// Ensure initKeysMap is only called once across the program’s runtime
	var initErr error
	initOnce.Do(func() {
		initErr = initKeysMap(issuerKeysDir)
	})
	if initErr != nil {
		return nil, errors.Wrap(initErr, "failed to initialize and/or migrate existing private key file")
	}

	activeKey, err := loadPEMFiles(issuerKeysDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load .pem files and find the most recent private key")
	}

	return activeKey, err
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
	key := issuerPrivateJWK.Load()
	if key == nil {
		// This returns issuerPrivateJWK if it's non-nil, or find and parse private JWK
		// located at IssuerKeysDirectory if there is one, or generate a new private key
		loadedKey, err := LoadIssuerPrivateKey(issuerKeysDir)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to load issuer private JWK")
		}
		key = &loadedKey
	}

	pkey, err := jwk.PublicKeyOf(*key)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate public key from file %v", issuerKeysDir)
	}

	if err = jwks.AddKey(pkey); err != nil {
		return nil, errors.Wrap(err, "Failed to add public key to new JWKS")
	}
	return jwks, nil
}

// Return the private JWK for the server to sign tokens
func GetIssuerPrivateJWK() (jwk.Key, error) {
	key := issuerPrivateJWK.Load()
	issuerKeysDir := param.IssuerKeysDirectory.GetString()
	currentIssuerKeysDir := getCurrentIssuerKeysDir()
	// Handles runtime changes to the issuer keys directory (configured via "IssuerKeysDirectory" parameter).
	// When the directory path changes:
	// 1. Resets the active private key
	// 2. Clears the in-memory cache of all private keys
	// Note: This does not affect the actual key files on disk.
	// Primarily used in the "invalid-token-sig-key", "diff-secrets-yield-diff-result" test scenario.
	var isDirChanged bool
	if currentIssuerKeysDir != issuerKeysDir {
		log.Debugf("The private keys dir generated by IssuerKeysDirectory param has changed from '%s' to '%s'", currentIssuerKeysDir, issuerKeysDir)
		ResetIssuerJWKPtr()
		ResetIssuerPrivateKeys()
		setCurrentIssuerKeysDir(issuerKeysDir)
		isDirChanged = true
	}

	if key == nil || isDirChanged {
		newKey, err := LoadIssuerPrivateKey(issuerKeysDir)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to load issuer private key")
		}
		key = &newKey
	}
	return *key, nil
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

	uid, err := GetDaemonUID()
	if err != nil {
		return err
	}

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
	if err := MkdirAll(keyDir, 0750, -1, gid); err != nil {
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
		cmd := exec.Command("icacls", secretLocation, "/grant", user+":F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "Failed to chown generated session secret %v to daemon group %v: %s",
				secretLocation, groupname, string(output))
		}
	} else { // Else we are running on linux/mac
		if err = os.Chown(secretLocation, uid, gid); err != nil {
			return errors.Wrapf(err, "Failed to chown generated session secret %v to daemon group %v",
				secretLocation, groupname)
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
