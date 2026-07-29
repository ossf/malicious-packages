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
	"time"
	"unicode"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ossf/malicious-packages/internal/gitname"
	"github.com/ossf/malicious-packages/internal/reportfilter"
)

const (
	// osvSchemaVersion is the current version of the OSV schema we are
	// generating. OSV processed will be upgraded to this version of the OSV
	// schema format.
	osvSchemaVersion = "1.7.4"

	// summaryFormat is the format string used to generate the summary.
	summaryFormat = "Malicious code in %s (%s)"
)

var (
	ErrInvalidOSV     = errors.New("invalid OSV")
	ErrUnexpectedOSV  = errors.New("unexpected OSV")
	ErrNormalizing    = errors.New("normalization error")
	ErrInvalidDetails = errors.New("invalid details")
	ErrSplitting      = errors.New("splitting error")

	ecosystemRE = regexp.MustCompile(`[ \/_-]+`)
)

type databaseSpecific struct {
	Origins []*OriginRef `json:"malicious-packages-origins"`
	IOCs    Indicators   `json:"iocs"`
}

type dbSpecificVuln struct {
	DatabaseSpecific databaseSpecific `json:"database_specific,omitempty"`
}

type Report struct {
	raw                   *osvschema.Vulnerability
	origins               []*OriginRef
	Ecosystem             string
	Name                  string
	allowMultipleAffected bool
}

// UnmarshalJSON implements the json.Unmarshaler interface.
//
// The implementation ensures that the resulting parsed data is valid for the
// purposes of tracking malicious packages.
//
// The implementation also extracts the database specific data tracking the
// origins the report.
func (r *Report) UnmarshalJSON(b []byte) error {
	r.raw = &osvschema.Vulnerability{}
	if err := protojson.Unmarshal(b, r.raw); err != nil {
		return err
	}
	var db dbSpecificVuln
	if err := json.Unmarshal(b, &db); err != nil {
		return fmt.Errorf("%w: invalid origins format: %w", ErrUnexpectedOSV, err)
	}
	r.origins = db.DatabaseSpecific.Origins

	// TODO: validate schema version is >= 1.4.0

	// Ensure the vuln object is valid.
	if err := validateVulnInternal(r.raw, r.allowMultipleAffected); err != nil {
		return err
	}

	// Populates the report-level Name and Ecosystem from the report - handling
	// git-based reports and canonicalizing the name.
	r.Name, r.Ecosystem = r.fetchNameAndEcosystem(r.raw)

	// Ensure the details can be parsed.
	if _, _, err := r.ParseDetails(); err != nil {
		return fmt.Errorf("%w: invalid details: %w", ErrInvalidDetails, err)
	}

	return nil
}

func (r *Report) MarshalJSON() ([]byte, error) {
	r.raw.SchemaVersion = osvSchemaVersion // Bump the schema version

	var dbMap map[string]any
	if r.raw.DatabaseSpecific != nil {
		dbMap = r.raw.DatabaseSpecific.AsMap()
	} else {
		dbMap = make(map[string]any)
	}

	if len(r.origins) > 0 {
		// This is a hack to transform the origins structure into a shape that can
		// be populated into the structpb.Struct. Serializing to JSON ensures that
		// all the fields have the correct keys and the values are properly
		// serialized when they are passed to structpb.NewStruct().
		b, err := json.Marshal(r.origins)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal origins: %w", err)
		}
		var origins []any
		if err := json.Unmarshal(b, &origins); err != nil {
			return nil, fmt.Errorf("failed to unmarshal origins: %w", err)
		}
		dbMap[originRefKey] = origins
	} else {
		// There are no origins, so remove them from dbMap.
		delete(dbMap, originRefKey)
	}

	dbStruct, err := structpb.NewStruct(dbMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create database_specific struct: %w", err)
	}
	r.raw.DatabaseSpecific = dbStruct

	opts := protojson.MarshalOptions{
		Indent: "  ",
	}
	return opts.Marshal(r.raw)
}

func (r *Report) Split() ([]*Report, error) {
	if len(r.raw.Affected) == 0 {
		return nil, nil
	}
	if len(r.raw.Affected) == 1 {
		return []*Report{r}, nil
	}
	if len(r.origins) > 1 {
		return nil, fmt.Errorf("%w: cannot split report with multiple origins", ErrSplitting)
	}

	var reports []*Report
	for i := range r.raw.Affected {
		newReport := proto.Clone(r.raw).(*osvschema.Vulnerability)
		newReport.Affected = []*osvschema.Affected{r.raw.Affected[i]}

		var origins []*OriginRef
		for _, o := range r.origins {
			cloned := &OriginRef{
				Source:       o.Source,
				SHASum:       o.SHASum,
				ImportTime:   o.ImportTime,
				ID:           o.ID,
				ModifiedTime: o.ModifiedTime,
				Ranges:       newReport.Affected[0].Ranges,
				Versions:     newReport.Affected[0].Versions,
			}
			origins = append(origins, cloned)
		}

		rep := &Report{
			raw:                   newReport,
			origins:               origins,
			allowMultipleAffected: false,
		}
		rep.Name, rep.Ecosystem = rep.fetchNameAndEcosystem(rep.raw)

		reports = append(reports, rep)
	}

	return reports, nil
}

type Reader struct {
	AllowMultipleAffected bool
}

func (r *Reader) ReadJSON(rdr io.Reader) (*Report, error) {
	b, err := io.ReadAll(rdr)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON: %w", err)
	}
	report := &Report{allowMultipleAffected: r.AllowMultipleAffected}
	if err := report.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return report, nil
}

func ReadJSON(r io.Reader) (*Report, error) {
	return (&Reader{}).ReadJSON(r)
}

func (r *Report) WriteJSON(w io.Writer) error {
	b, err := r.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	_, err = w.Write(b)
	return err
}

// Path returns a directory name for where the report will be placed.
//
// This dir must be considered unsafe and checked before usage.
func (r *Report) Path() string {
	// TODO: handle path casing better when it becomes a problem.
	return filepath.Join(cleanEcosystem(r.Ecosystem), strings.ToLower(r.Name))
}

// ID returns the ID for the report.
//
// If no ID has been assigned the value will be the empty string.
func (r *Report) ID() string {
	return r.raw.Id
}

// StripID removes the ID for the report.
func (r *Report) StripID() {
	r.raw.Id = ""
}

// ApplyFilter applies the filter to the report.
func (r *Report) ApplyFilter(f reportfilter.Filter) {
	f.Apply(r.raw)
}

// AliasID will add the ID for the report into the aliases section.
//
// If no ID has been assigned, this function is a no-op.
func (r *Report) AliasID() {
	if r.raw.Id == "" {
		// No ID.
		return
	}
	if slices.Contains(r.raw.Aliases, r.raw.Id) {
		// ID is already present in aliases. Don't add it again.
		return
	}
	r.raw.Aliases = append(r.raw.Aliases, r.raw.Id)
}

// FilterSelf will remove any refences to this report based on its ID from
// aliases or references.
//
// If no ID has been assigned, this function is a no-op.
func (r *Report) FilterSelf() {
	if r.raw.Id == "" {
		// No ID.
		return
	}
	r.raw.Aliases = slices.DeleteFunc(r.raw.Aliases, func(s string) bool {
		return r.raw.Id == s
	})
	r.raw.References = slices.DeleteFunc(r.raw.References, func(ref *osvschema.Reference) bool {
		return ref != nil && strings.HasSuffix(ref.Url, fmt.Sprintf("/%s.json", r.raw.Id))
	})
}

// IsWithdrawn returns whether or not the report has been withdrawn.
func (r *Report) IsWithdrawn() bool {
	return r.raw.Withdrawn != nil && r.raw.Withdrawn.IsValid() && !r.raw.Withdrawn.AsTime().IsZero()
}

// Published returns the published time for the report.
func (r *Report) Published() time.Time {
	if r.raw.Published != nil && r.raw.Published.IsValid() {
		return r.raw.Published.AsTime()
	}
	return time.Time{}
}

// IsRecursive returns whether or not the report may be recursive. This function
// only makes sense to use during ingestion.
func (r *Report) IsRecursive() bool {
	if r.HasDetailsHeader() {
		return true
	}
	if strings.Contains(r.raw.Details, "Credit: [OpenSSF](https://github.com/ossf/malicious-packages)") {
		return true
	}
	return false
}

// urlEcosystems contains a set of OSV ecosystems that allow a registry URL
// to be specified after the ecosystem name, separated by a colon.
var urlEcosystems = []osvconstants.Ecosystem{
	osvconstants.EcosystemMaven,
	osvconstants.EcosystemVSCode,
}

func cleanEcosystem(in string) string {
	e, extra, found := strings.Cut(in, ":")
	if found && slices.Contains(urlEcosystems, osvconstants.Ecosystem(e)) {
		// Remove the scheme to make the URL look more pretty in the filesystem.
		extra, _ = strings.CutPrefix(extra, "https://")
		in = e + ":" + extra
	}
	out := ecosystemRE.ReplaceAllString(in, "-")
	return strings.ToLower(out)
}

func (r *Report) fetchNameAndEcosystem(v *osvschema.Vulnerability) (string, string) {
	// Assumes that the vulnerability "v" has already been validated.
	pkg := v.Affected[0].Package

	// If package is entirely empty, assume we are using a git-based ecosystem.
	if isPackageEmpty(pkg) {
		name := r.raw.Affected[0].Ranges[0].Repo
		// Run the name through the canonicalization so it is always consistent.
		return gitname.CanonForStorage(name), string(ecosystemGit)
	}

	return canonicalizeName(pkg.Name, osvconstants.Ecosystem(pkg.Ecosystem)), pkg.Ecosystem
}

func (r *Report) Normalize() error {
	if r.raw.Id != "" {
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

	// If any ranges have the type GIT, then canonicalize the repository.
	ranges := r.raw.Affected[0].Ranges
	for i := range ranges {
		if ranges[i].Type == osvschema.Range_GIT {
			repo, err := gitname.Parse(ranges[i].Repo)
			if err != nil {
				return fmt.Errorf("%w: git repository invalid: %w", ErrNormalizing, err)
			}
			ranges[i].Repo = gitname.Canon(repo).String()
		}
	}

	return nil
}

// canonicalizeName transforms name to conform to the canonical value for the
// given ecosystem.
// If package names for an ecosystem may contain mixed case, but are compared
// as case insensitive, then equalName should be changed to preserve the case
// of the first package seen.
func canonicalizeName(name string, ecosystem osvconstants.Ecosystem) string {
	switch ecosystem {
	case osvconstants.EcosystemCratesIO:
		// The canonical form for crates.io names is lowercase with dashes
		// replaced by underscores.
		// See: https://github.com/rust-lang/crates.io/blob/master/migrations/20150319224700_dumped_migration_93/up.sql
		return strings.ReplaceAll(strings.ToLower(name), "-", "_")
	case osvconstants.EcosystemPyPI:
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
	case ecosystemGit:
		// CanonForStorage is called for the name earlier during UnmarshalJSON
		return name
	default:
		// Reasonable default is to do nothing
		return name
	}
}

func stripUnexpectedValues(st *structpb.Struct) *structpb.Struct {
	if st == nil {
		return nil
	}
	obj := st.AsMap()
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
	res, err := structpb.NewStruct(cleaned)
	if err != nil {
		panic(err)
	}
	return res
}

func FromFile(filename string) (*Report, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed opening %s: %w", filename, err)
	}
	defer fd.Close()
	return ReadJSON(fd)
}
