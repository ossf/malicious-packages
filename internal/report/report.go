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
	"slices"
	"strings"
	"unicode"

	"github.com/google/osv-scanner/pkg/models"
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
	IOCs    Indicators   `json:"iocs"`
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

	// Ensure the vuln object is valid.
	if err := ValidateVuln(r.raw); err != nil {
		return err
	}

	r.Ecosystem = string(r.raw.Affected[0].Package.Ecosystem)
	r.Name = r.raw.Affected[0].Package.Name

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

// FilterSelf will remove any refences to this report based on its ID from
// aliases or references.
//
// If no ID has been assigned, this function is a no-op.
func (r *Report) FilterSelf() {
	if r.raw.ID == "" {
		// No ID.
		return
	}
	r.raw.Aliases = slices.DeleteFunc(r.raw.Aliases, func(s string) bool {
		return r.raw.ID == s
	})
	r.raw.References = slices.DeleteFunc(r.raw.References, func(ref models.Reference) bool {
		return strings.HasSuffix(ref.URL, fmt.Sprintf("/%s.json", r.raw.ID))
	})
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

	r.Name = canonicalizeName(r.Name, models.Ecosystem(r.Ecosystem))

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

// canonicalizeName transforms name to conform to the canonical value for the
// given ecosystem.
// If package names for an ecosystem may contain mixed case, but are compared
// as case insensitive, then equalName should be changed to preserve the case
// of the first package seen.
func canonicalizeName(name string, ecosystem models.Ecosystem) string {
	switch ecosystem {
	case models.EcosystemCratesIO:
		// The canonical form for crates.io names is lowercase with dashes
		// replaced by underscores.
		// See: https://github.com/rust-lang/crates.io/blob/master/migrations/20150319224700_dumped_migration_93/up.sql
		return strings.Replace(strings.ToLower(name), "-", "_", -1)
	case models.EcosystemPyPI:
		// Replace runs of [-_.] with a single "-", then lowercase everything.
		// See: https://github.com/pypa/pip/blob/24.0/src/pip/_vendor/packaging/utils.py
		// See: https://www.python.org/dev/peps/pep-0503/
		run := false
		return strings.Map(func(r rune) rune {
			if r == '-' || r == '_' || r == '.' {
				if run {
					return -1
				}
				run = true
				return '-'
			}
			run = false
			return unicode.ToLower(r)
		}, name)
	default:
		// Reasonable default is to do nothing
		return name
	}
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
