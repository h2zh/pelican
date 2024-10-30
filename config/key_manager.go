package config

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	defaultPrivateKeyDir = "/etc/pelican/private-keys" // TODO: change it to a param
)

type KeyManager struct {
	keys     map[string]jwk.Key // Map of key ID to jwk.Key
	keyDir   string
	keyMutex sync.RWMutex
}

var (
	globalKeyManager *KeyManager
	managerOnce      sync.Once
)

// GetKeyManager returns the singleton KeyManager instance
func GetKeyManager() *KeyManager {
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

	kid := key.KeyID()
	if kid == "" {
		kid = "legacy-key"
	}

	// Write to new location
	newPath := filepath.Join(km.keyDir, fmt.Sprintf("%s.pem", kid))
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

		keyPath := filepath.Join(km.keyDir, file.Name())
		key, err := km.loadSinglePrivateKey(keyPath)
		if err != nil {
			log.Warnf("Failed to load key %s: %v", keyPath, err)
			continue
		}

		// Skip if the key is already loaded
		if _, exists := km.keys[key.KeyID()]; exists {
			continue
		}

		km.keys[key.KeyID()] = key
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

// GetActivePrivateKey returns the current active key for signing
func (km *KeyManager) GetActivePrivateKey() (jwk.Key, error) {
	km.keyMutex.RLock()
	defer km.keyMutex.RUnlock()

	// If no keys exist, generate one
	if len(km.keys) == 0 {
		return km.generateNewPrivateKey()
	}

	// For now, return the first key (TODO: implement more sophisticated key selection)
	for _, key := range km.keys {
		return key, nil
	}

	return nil, errors.New("No active key available")
}

// generateNewPrivateKey creates a new key and adds it to the manager
func (km *KeyManager) generateNewPrivateKey() (jwk.Key, error) {
	km.keyMutex.Lock()
	defer km.keyMutex.Unlock()

	keyPath := filepath.Join(km.keyDir, fmt.Sprintf("key-%d.pem", time.Now().Unix()))
	if err := GeneratePrivateKey(keyPath, elliptic.P256(), false); err != nil {
		return nil, errors.Wrap(err, "Failed to generate new private key")
	}

	key, err := km.loadSinglePrivateKey(keyPath)
	if err != nil {
		return nil, err
	}

	km.keys[key.KeyID()] = key
	return key, nil
}

// GetKeyByID returns a specific key by its ID
func (km *KeyManager) GetPrivateKeyByID(kid string) (jwk.Key, bool) {
	km.keyMutex.RLock()
	defer km.keyMutex.RUnlock()

	key, exists := km.keys[kid]
	return key, exists
}

// LaunchPrivateKeysDirRefresh checks the directory for new .pem files every 10 minutes
// and loads new private keys if a new file is found.
func LaunchPrivateKeysDirRefresh(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(10 * time.Minute)
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
					log.Debugln("All private keys loaded successfully.")
				}
			}
		}
	})
}
