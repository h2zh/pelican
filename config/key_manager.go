package config

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type KeyManager struct {
	keys     map[string]jwk.Key // Map filename (e.g. `1730394365.pem`, also used as timestamp) to jwk.Key
	keyDir   string
	keyMutex sync.RWMutex
}

var (
	globalKeyManager *KeyManager
	managerOnce      sync.Once
)

// GetKeyManager returns the singleton KeyManager instance
func GetKeyManager() *KeyManager {
	defaultPrivateKeyDir := strings.Replace(param.IssuerKey.GetString(), "issuer.jwk", "private-keys", 1)
	managerOnce.Do(func() {
		globalKeyManager = &KeyManager{
			keys:   make(map[string]jwk.Key),
			keyDir: defaultPrivateKeyDir,
		}
	})
	return globalKeyManager
}

// Initialize sets up the key directory and loads existing keys
func (km *KeyManager) Initialize() error {
	gid, err := GetDaemonGID()
	if err != nil {
		return err
	}
	// Create key directory if it doesn't exist
	if err := MkdirAll(km.keyDir, 0750, -1, gid); err != nil {
		return errors.Wrap(err, "Failed to create key directory")
	}

	// Try to migrate legacy key if it exists
	if err := km.migrateLegacyPrivateKey(); err != nil {
		log.Warnf("Failed to migrate legacy key: %v", err)
		// Continue execution - we'll create a new key if no key found
	}

	// Load all keys from directory
	if err := km.loadPrivateKeysFromDirectory(); err != nil {
		log.Warnf("Failed to load keys from directory: %v", err)
		// Continue execution - we'll create a new key if no key found
	}

	// Check if we have any keys after migration and loading
	km.keyMutex.RLock()
	keyCount := len(km.keys)
	km.keyMutex.RUnlock()

	if keyCount == 0 {
		log.Info("No existing keys found. Generating new initial key...")
		_, err := km.generateNewPrivateKey()
		if err != nil {
			return errors.Wrap(err, "Failed to generate initial key")
		}
		log.Info("Successfully generated initial key")
	}

	return nil
}

// migrateLegacyPrivateKey moves the old single key file to the new directory structure
func (km *KeyManager) migrateLegacyPrivateKey() error {
	legacyPrivateKeyFile := param.IssuerKey.GetString()

	if _, err := os.Stat(legacyPrivateKeyFile); os.IsNotExist(err) {
		return nil // No legacy key exists
	}

	contents, err := os.ReadFile(legacyPrivateKeyFile)
	if err != nil {
		return errors.Wrap(err, "Failed to read legacy key file")
	}

	// Parse the key to get its key ID
	key, err := jwk.ParseKey(contents, jwk.WithPEM(true))
	if err != nil {
		return errors.Wrap(err, "Failed to parse legacy key")
	}

	if err := jwk.AssignKeyID(key); err != nil {
		return errors.Wrap(err, "Failed to assign key ID to legacy key")
	}

	// Write to new location
	newPath := filepath.Join(km.keyDir, fmt.Sprintf("%d.pem", time.Now().Unix()))
	if err := os.WriteFile(newPath, contents, 0400); err != nil {
		return errors.Wrap(err, "Failed to write legacy key to new location")
	}

	return nil
}

// loadPrivateKeysFromDirectory loads all .pem files from the key directory
func (km *KeyManager) loadPrivateKeysFromDirectory() error {
	km.keyMutex.Lock()
	defer km.keyMutex.Unlock()

	files, err := os.ReadDir(km.keyDir)
	if err != nil {
		return errors.Wrap(err, "Failed to read key directory")
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".pem" {
			continue
		}

		// Skip if the key is already loaded
		if _, exists := km.keys[file.Name()]; exists {
			continue
		}

		keyPath := filepath.Join(km.keyDir, file.Name())
		key, err := km.loadSinglePrivateKey(keyPath)
		if err != nil {
			log.Warnf("Failed to load key %s: %v", keyPath, err)
			continue
		}

		km.keys[file.Name()] = key
		log.Debugf("Loaded the private key in %s into the key manager", file.Name())
	}

	return nil
}

// loadSinglePrivateKey loads and prepares a single key file
func (km *KeyManager) loadSinglePrivateKey(path string) (jwk.Key, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read key file")
	}

	key, err := jwk.ParseKey(contents, jwk.WithPEM(true))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse key")
	}

	// Add the algorithm to the key
	if err := key.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return nil, errors.Wrap(err, "Failed to set algorithm")
	}

	// Ensure key has an ID
	if err := jwk.AssignKeyID(key); err != nil {
		return nil, errors.Wrap(err, "Failed to assign key ID")
	}

	return key, nil
}

// GetActivePrivateKey returns the latest created key for signing
func (km *KeyManager) GetActivePrivateKey() (jwk.Key, error) {
	km.keyMutex.RLock()
	defer km.keyMutex.RUnlock()

	// If no keys exist, generate one
	if len(km.keys) == 0 {
		return km.generateNewPrivateKey()
	}

	var (
		latestKey            jwk.Key
		latestKeyCreatedTime int64 = 0
		validKeyFound        bool  = false
	)

	// For now, return the most recent created key (future TODO: implement key selection by the admin)
	for filename, key := range km.keys {
		// Parse the .pem file creation time from filename
		var keyCreatedTimeStr string
		pos := strings.Index(filename, ".pem")
		if pos != -1 {
			keyCreatedTimeStr = filename[:pos]
		} else {
			log.Warnf("Skipped file %s because it doesn't match the naming pattern", filename)
			continue
		}
		keyCreatedTime, err := strconv.ParseInt(keyCreatedTimeStr, 10, 64)
		if err != nil {
			log.Warnf("Cannot convert %s to number", keyCreatedTimeStr)
			continue
		}
		// Compare the timestamp of all keys to get the most recent one
		if !validKeyFound || keyCreatedTime > latestKeyCreatedTime {
			latestKey = key
			latestKeyCreatedTime = keyCreatedTime
			validKeyFound = true
		}
	}

	if !validKeyFound {
		return nil, errors.New("No active key available")
	}
	log.Debugln("Current private keys in the memory:")
	for filename, _ := range km.keys {
		log.Debugln(filename)
	}
	log.Debugf("Current private keys in use: %d.pem", latestKeyCreatedTime)
	return latestKey, nil
}

// generateNewPrivateKey creates a new key and adds it to the manager
func (km *KeyManager) generateNewPrivateKey() (jwk.Key, error) {
	km.keyMutex.Lock()
	defer km.keyMutex.Unlock()

	filename := fmt.Sprintf("%d.pem", time.Now().Unix())
	keyPath := filepath.Join(km.keyDir, filename)
	if err := GeneratePrivateKey(keyPath, elliptic.P256(), false); err != nil {
		return nil, errors.Wrap(err, "Failed to generate new private key")
	}

	key, err := km.loadSinglePrivateKey(keyPath)
	if err != nil {
		return nil, err
	}

	km.keys[filename] = key
	return key, nil
}

// LaunchPrivateKeysDirRefresh checks the directory for new .pem files every 10 minutes
// and loads new private keys if a new file is found.
func LaunchPrivateKeysDirRefresh(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Debugln("Stopping periodic check for private keys directory.")
				return nil
			case <-ticker.C:
				if err := globalKeyManager.loadPrivateKeysFromDirectory(); err != nil {
					log.Errorf("Error loading private keys: %v", err)
				} else {
					log.Debugln("Private keys directory refreshed successfully.")
				}

				key, err := globalKeyManager.GetActivePrivateKey()
				if err != nil {
					log.Errorf("Failed to get private key in use")
				}
				UpdateIssuerJWKPtr(key)
				log.Debugf("Successfully update the private key in use in memory, kid: %s", key.KeyID())

			}
		}
	})
}
