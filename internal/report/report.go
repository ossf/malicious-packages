// Copyright 2022 Malicious Packages Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/osv-scanner/pkg/models"
)

var (
	ErrInvalidOSV    = errors.New("invalid OSV")
	ErrUnexpectedOSV = errors.New("unexpected OSV")

	ecosystemRE  = regexp.MustCompile(`[ \/._-]+`)
	originRefKey = "malicious-packages-origins"
)

type databaseSpecific struct {
	Origins []*originRef `json:"malicious-packages-origins"`
}

type dbSpecificVuln struct {
	DatabaseSpecific databaseSpecific `json:"database_specific,omitempty"`
}

type originRef struct {
	Source     string         `json:"source"`
	SHASum     string         `json:"sha256"`
	ImportTime time.Time      `json:"import_time"`
	Ranges     []models.Range `json:"ranges,omitempty"`
	Versions   []string       `json:"versions,omitempty"`
}

type Report struct {
	raw       *models.Vulnerability
	origins   []*originRef
	Ecosystem string
	Name      string
}

// UnmarshalJSON implements the json.Unmashaler interface.
//
// The implementation ensures that the resulting parsed data is valid for the
// purposes of tracking malicious packages.
//
// The implementation also extracts the database specific data tracking the
// origins the report.
func (r *Report) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &(r.raw)); err != nil {
		return err
	}
	var db dbSpecificVuln
	if err := json.Unmarshal(b, &db); err != nil {
		return fmt.Errorf("%w: invalid origins format: %w", ErrUnexpectedOSV, err)
	}
	r.origins = db.DatabaseSpecific.Origins

	if len(r.raw.Affected) == 0 {
		return fmt.Errorf("%w: no affected packages listed", ErrInvalidOSV)
	}
	if len(r.raw.Affected) > 1 {
		return fmt.Errorf("%w: multiple affected entries", ErrUnexpectedOSV)
	}
	r.Ecosystem = string(r.raw.Affected[0].Package.Ecosystem)
	if r.Ecosystem == "" {
		return fmt.Errorf("%w: package ecosystem is missing", ErrInvalidOSV)
	}
	r.Name = r.raw.Affected[0].Package.Name
	if r.Name == "" {
		return fmt.Errorf("%w: package name is missing", ErrInvalidOSV)
	}
	return nil
}

func (r *Report) MarshalJSON() ([]byte, error) {
	if r.raw.DatabaseSpecific == nil {
		r.raw.DatabaseSpecific = make(map[string]interface{})
	}
	r.raw.DatabaseSpecific[originRefKey] = r.origins

	return json.Marshal(r.raw)
}

func ReadJSON(r io.Reader) (*Report, error) {
	// parse the OSV into an arbitrary struct so we don't lose any data.
	report := &Report{}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&(report)); err != nil {
		// TODO: separate "syntax errors" from IO errors
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return report, nil
}

func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

// Path returns a directory name for where the report will be placed.
//
// This dir must be considered unsafe and checked before usage.
func (r *Report) Path() string {
	return filepath.Join(cleanEcosystem(r.Ecosystem), strings.ToLower(r.Name))
}

func cleanEcosystem(in string) string {
	out := ecosystemRE.ReplaceAllString(in, "-")
	return strings.ToLower(out)
}

func (r *Report) HasOrigin(sourceID, shasum string) bool {
	for _, o := range r.origins {
		if o.Source == sourceID && o.SHASum == shasum {
			return true
		}
	}
	return false
}

func (r *Report) SetOrigin(sourceID, shasum string) {
	ref := &originRef{
		Source:     sourceID,
		SHASum:     shasum,
		ImportTime: time.Now().UTC(),
		Ranges:     r.raw.Affected[0].Ranges,
		Versions:   r.raw.Affected[0].Versions,
	}
	r.origins = append(r.origins, ref)
}
