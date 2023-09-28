// Copyright 2023 Malicious Packages Authors
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
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
)

const (
	// osvSchemaVersion is the current version of the OSV schema we are
	// generating. OSV processed will be upgraded to this version of the OSV
	// schema format.
	osvSchemaVersion = "1.5.0"

	// summaryFormat is the format string used to generate the summary.
	summaryFormat = "Malicious code in %s (%s)"
)

var (
	ErrInvalidOSV     = errors.New("invalid OSV")
	ErrUnexpectedOSV  = errors.New("unexpected OSV")
	ErrNormalizing    = errors.New("normalization error")
	ErrInvalidDetails = errors.New("invalid details")

	ecosystemRE = regexp.MustCompile(`[ \/._-]+`)
)

type databaseSpecific struct {
	Origins []*OriginRef `json:"malicious-packages-origins"`
}

type dbSpecificVuln struct {
	DatabaseSpecific databaseSpecific `json:"database_specific,omitempty"`
}

type Report struct {
	raw       *models.Vulnerability
	origins   []*OriginRef
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

	// TODO: validate schema version is >= 1.4.0

	// Must have one and only one Affected entry.
	if len(r.raw.Affected) == 0 {
		return fmt.Errorf("%w: no affected packages listed", ErrInvalidOSV)
	}
	if len(r.raw.Affected) > 1 {
		return fmt.Errorf("%w: multiple affected entries", ErrUnexpectedOSV)
	}

	// Ecosystem must be set, and must be in the predefined set of ecosystems.
	// Note: the OSV schema allows for ecosystems to append information after a
	// colon (':') character.
	r.Ecosystem = string(r.raw.Affected[0].Package.Ecosystem)
	if r.Ecosystem == "" {
		return fmt.Errorf("%w: package ecosystem is missing", ErrInvalidOSV)
	}
	if e, _, _ := strings.Cut(r.Ecosystem, ":"); !slices.Contains(models.Ecosystems, models.Ecosystem(e)) {
		return fmt.Errorf("%w: package ecosystem '%s' is invalid", ErrInvalidOSV, e)
	}

	// Package name must be set.
	r.Name = r.raw.Affected[0].Package.Name
	if r.Name == "" {
		return fmt.Errorf("%w: package name is missing", ErrInvalidOSV)
	}
	return nil
}

func (r *Report) MarshalJSON() ([]byte, error) {
	r.raw.SchemaVersion = osvSchemaVersion // Bump the schema version
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

// ID returns the ID for the report.
//
// If no ID has been assigned the value will be the empty string.
func (r *Report) ID() string {
	return r.raw.ID
}

// StripID removes the ID for the report.
func (r *Report) StripID() {
	r.raw.ID = ""
}

// AliasID will add the ID for the report into the aliases section.
//
// If no ID has been assigned, this function is a no-op.
func (r *Report) AliasID() {
	if r.raw.ID == "" {
		// No ID.
		return
	}
	if slices.Contains(r.raw.Aliases, r.raw.ID) {
		// ID is already present in aliases. Don't add it again.
		return
	}
	r.raw.Aliases = append(r.raw.Aliases, r.raw.ID)
}

// IsWithdrawn returns whether or not the report has been withdrawn.
func (r *Report) IsWithdrawn() bool {
	return !r.raw.Withdrawn.IsZero()
}

func cleanEcosystem(in string) string {
	out := ecosystemRE.ReplaceAllString(in, "-")
	return strings.ToLower(out)
}

func (r *Report) Normalize() error {
	if r.raw.ID != "" {
		// Only normalize reports which currently don't have an ID assigned.
		return nil
	}

	r.raw.Summary = fmt.Sprintf(summaryFormat, r.Name, r.Ecosystem)
	r.raw.Affected[0].DatabaseSpecific = stripUnexpectedValues(r.raw.Affected[0].DatabaseSpecific)
	r.raw.DatabaseSpecific = stripUnexpectedValues(r.raw.DatabaseSpecific)

	if len(r.origins) > 1 {
		return fmt.Errorf("%w: normalizing must be done before merge", ErrNormalizing)
	}

	if strings.Contains(r.raw.Details, detailHeader) {
		// Abort early if we have already added the header.
		return fmt.Errorf("%w: header already present in details", ErrNormalizing)
	}

	if len(r.origins) == 1 {
		r.SetDetails("", map[*OriginRef]string{
			r.origins[0]: r.raw.Details,
		})
	}

	return nil
}

func stripUnexpectedValues(obj map[string]any) map[string]any {
	cleaned := make(map[string]any)
	for k, v := range obj {
		switch v.(type) {
		case map[string]any:
		case []any:
		default:
			// noop - scalars, and other unexpected types are removed.
			continue
		}
		cleaned[k] = v
	}
	return cleaned
}

func FromFile(filename string) (*Report, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed opening %s: %w", filename, err)
	}
	defer fd.Close()
	return ReadJSON(fd)
}
