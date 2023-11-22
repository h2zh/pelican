//go:build windows

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package origin_ui

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func doReload() error {
	db := authDB.Load()
	if db == nil {
		log.Debug("Cannot reload auth database - not configured")
		return nil
	}
	err := db.Reload(nil)
	if err != nil {
		log.Warningln("Failed to reload auth database:", err)
		return err
	}
	log.Debug("Successfully reloaded the auth database")
	return nil
}

func WritePasswordEntry(_, _ string) error {
	return errors.New("WritePasswordEntry not implemented on Windows")
}
