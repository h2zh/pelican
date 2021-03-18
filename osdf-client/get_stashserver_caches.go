package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

func get_stashservers_caches(responselines_b [][]byte) ([]string, error) {

	/**
		 After the geo order of the selected server list on line zero,
	      the rest of the response is in .cvmfswhitelist format.
	     This is done to avoid using https for every request on the
	      wlcg-wpad servers and takes advantage of conveniently
	      existing infrastructure.
	     The format contains the following lines:
	     1. Creation date stamp, e.g. 20200414170005.  For debugging
	        only.
	     2. Expiration date stamp, e.g. E20200421170005.  cvmfs clients
	        check this to avoid replay attacks, but for this api that
	        is not much of a risk so it is ignored.
	     3. "Repository" name, e.g. Nstash-servers.  cvmfs clients
	        also check this but it is not important here.
	     4. With cvmfs the 4th line has a repository fingerprint, but
	        for this api it instead contains a semi-colon separated list
	        of named server lists.  Each server list is of the form
	        name=servers where servers is comma-separated.  Ends with
	        "hash=-sha1" because cvmfs_server expects the hash name
	        to be there.  e.g.
	        xroot=stashcache.t2.ucsd.edu,sg-gftp.pace.gatech.edu;xroots=xrootd-local.unl.edu,stashcache.t2.ucsd.edu;hash=-sha1
	     5. A two-dash separator, i.e "--"
	     6. The sha1 hash of lines 1 through 4.
	     7. The signature, i.e. an RSA encryption of the hash that can
	        be decrypted by the OSG cvmfs public key.  Contains binary
	        information so it may contain a variable number of newlines
	        which would have caused it to have been split into multiple
		    response "lines".
		**/

	if len(responselines_b) < 8 {

		log.Errorln("stashservers response too short, less than 8 lines:", len(responselines_b))
		return []string{}, errors.New("stashservers response too short, less than 8 lines")
	}

	// Get the 5th row (4th index), the last 5 characters
	hashname_b := string(responselines_b[4][len(responselines_b[4])-5:])

	if hashname_b != "-sha1" {

		log.Error("stashservers response does not have sha1 hash: %s", string(hashname_b))
		return []string{}, errors.New("stashservers response does not have sha1 hash")
	}

	var hashedTextBuilder strings.Builder
	// Loop through response lines 1 through 4
	for i := 1; i < 5; i++ {
		hashedTextBuilder.WriteString(string(responselines_b[i]))
		hashedTextBuilder.WriteString("\n")
	}
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(hashedTextBuilder.String()))
	hashed := sha1Hash.Sum(nil)
	hashStr := hex.EncodeToString(hashed)

	log.Debugln("Hashed:", hashStr, "From CVMFS:", string(responselines_b[6]))
	if string(responselines_b[6]) != hashStr {
		log.Debugln("stashservers hash %s does not match expected hash %s", string(responselines_b[6]), hashname_b)
		log.Debugln("hashed text:\n%s", string(hashname_b))
		log.Errorln("stashservers response hash does not match expected hash")
		return nil, errors.New("stashservers response hash does not match expected hash")
	}

	// Call out to /usr/bin/openssl if present, in order to avoid
	// python dependency on a crypto package.

	//
	var pubKey *rsa.PublicKey
	var err error
	if pubKey, err = readPublicKey(); err != nil {
		// The signature check isn't critical to be done everywhere;
		// any tampering will likely to be caught somewhere and
		// investigated.  Usually openssl is present.
		log.Warnln("Public Key not found, will not verify caches")
	} else {
		sig := responselines_b[7]
		ioutil.WriteFile("sig", sig, 0644)
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hashed[:], sig)
		if err != nil {
			log.Errorln("Error from public key verification:", err)
			//return nil, err
		} else {
			log.Debugln("Signature Matched")
		}

	}
	log.Debugf("Cache list: %s", string(responselines_b[4]))
	cacheColonList := strings.Split(string(responselines_b[4]), "=")[1]
	cacheListStr := strings.Split(cacheColonList, ";")[0]
	cacheList := strings.Split(cacheListStr, ",")
	log.Debugln("Cache list:", cacheList)

	if print_cache_list_names {
		for index, cache := range cacheList {
			fmt.Print(cache)

			// If it's the last item in the list, then don't add the comma
			if index != len(cacheList)-1 {
				fmt.Print(", ")
			}
		}
	}

	for i, _ := range cacheList {
		cacheList[i] = "root://" + cacheList[i]
	}

	return cacheList, nil

}

func getKeyLocation() string {
	osgpub := "opensciencegrid.org.pub"
	var checkedLocation string = path.Join("/etc/cvmfs/keys/opensciencegrid.org/", osgpub)
	if _, err := os.Stat(checkedLocation); err == nil {
		return checkedLocation
	}
	prefix := os.Getenv("OSG_LOCATION")
	if prefix != "" {
		checkedLocation = path.Join(prefix, "etc/stashcache", osgpub)
		if _, err := os.Stat(checkedLocation); err == nil {
			return checkedLocation
		}
		checkedLocation = path.Join(prefix, "usr/share/stashcache", osgpub)
		if _, err := os.Stat(checkedLocation); err == nil {
			return checkedLocation
		}

	}

	// Try the current directory
	checkedLocation, _ = filepath.Abs(osgpub)
	if _, err := os.Stat(checkedLocation); err == nil {
		return checkedLocation
	}
	return ""

}

// Largely adapted from https://gist.github.com/jshap70/259a87a7146393aab5819873a193b88c
func readPublicKey() (*rsa.PublicKey, error) {

	publicKeyPath := getKeyLocation()
	if publicKeyPath == "" {
		return nil, errors.New("Public Key not found")
	}

	pubkeyContents, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		log.Errorln("Error reading public key:", err)
		return nil, err
	}

	pubPem, rest := pem.Decode(pubkeyContents)
	if pubPem.Type != "PUBLIC KEY" {
		log.WithFields(log.Fields{"PEM Type": pubPem.Type}).Error("RSA public key is of the wrong type")
		return nil, errors.New("RSA public key is of the wrong type")
	}
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		log.Errorln("Unable to parse RSA public key:", err)
		return nil, errors.New("Unable to parse RSA public key")
	}
	log.Debugf("Got a %T, with remaining data: %q", parsedKey, rest)

	var pubKey *rsa.PublicKey
	var ok bool
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		log.Errorln("Failed to convert RSA public key")
	}

	return pubKey, nil

}
