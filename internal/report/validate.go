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
	"crypto/sha1" //nolint:gosec // only used for constants
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/package-url/packageurl-go"

	"github.com/ossf/malicious-packages/internal/gitname"
)

const (
	// ecosystemGit is synthetic ecosystem used when a git-based report is being
	// processed, since those reports do not have any package data.
	ecosystemGit = osvconstants.Ecosystem("Git")
)

var supportedEcosystems = []osvconstants.Ecosystem{
	osvconstants.EcosystemAlpine,
	osvconstants.EcosystemCratesIO,
	osvconstants.EcosystemDebian,
	osvconstants.EcosystemGo,
	osvconstants.EcosystemHex,
	osvconstants.EcosystemMaven,
	osvconstants.EcosystemNPM,
	osvconstants.EcosystemNuGet,
	osvconstants.EcosystemOSSFuzz,
	osvconstants.EcosystemPackagist,
	osvconstants.EcosystemPyPI,
	osvconstants.EcosystemRubyGems,
	osvconstants.EcosystemUbuntu,
	osvconstants.EcosystemVSCode,
}

// ValidateVuln ensures that v conforms to the the OSV Schema, and to the
// specific constraints expected by the repository.
func ValidateVuln(v *osvschema.Vulnerability) error {
	return validateVulnInternal(v, false)
}

func validateVulnInternal(v *osvschema.Vulnerability, allowMultiple bool) error {
	// A malicious packages vuln must have one and only one Affected entry. We
	// allow multiple only on a per-source basis, but once they are ingested they
	// must conform to the single Affected entry rule.
	if len(v.Affected) == 0 {
		return fmt.Errorf("%w: no affected packages listed", ErrInvalidOSV)
	}
	if len(v.Affected) > 1 {
		if !allowMultiple {
			// Multiple affected are not allowed, so return an error.
			return fmt.Errorf("%w: multiple affected entries", ErrUnexpectedOSV)
		}
		// Ensure that if multiple affected are allowed there are no duplicate
		// ecocystem + package name entries.
		seen := make(map[string]bool)
		for i := range v.Affected {
			pkg := v.Affected[i].Package
			if pkg == nil {
				// Ensure empty package names are checked.
				pkg = &osvschema.Package{}
			}
			name := canonicalizeName(pkg.Name, osvconstants.Ecosystem(pkg.Ecosystem))
			key := fmt.Sprintf("%s!!%s", pkg.Ecosystem, name)
			if seen[key] {
				return fmt.Errorf("%w: duplicate affected package %s in %s", ErrUnexpectedOSV, name, pkg.Ecosystem)
			}
			seen[key] = true
		}
	}

	for i := range v.Affected {
		ecosystem, err := validatePackage(v.Affected[i].Package)
		if err != nil {
			return err
		}

		if ecosystem == ecosystemGit && len(v.Affected[i].Ranges) == 0 {
			// Git-based reports must have at least one range so we know the
			// repository the report is for.
			return fmt.Errorf("%w: git-based report has no ranges", ErrUnexpectedOSV)
		}

		// Validate the ranges are correct.
		repoSet := map[string]bool{}
		for _, rng := range v.Affected[i].Ranges {
			if err := validateRange(rng, ecosystem); err != nil {
				return err
			}
			if rng.Repo != "" {
				repoSet[rng.Repo] = true
			}
		}

		// If we are Git-based, ensure all the repos are the same for the ranges.
		if ecosystem == ecosystemGit && len(repoSet) > 1 {
			repos := slices.Collect(maps.Keys(repoSet))
			return fmt.Errorf("%w: git-based report has multiple repos: %s", ErrUnexpectedOSV, repos)
		}

		// Ensure ecosystem specific data is not present.
		if es := v.Affected[i].EcosystemSpecific; len(es) > 0 {
			return fmt.Errorf("%w: ecosystem_specific must not be set", ErrUnexpectedOSV)
		}
	}

	return nil
}

func isPackageEmpty(pkg *osvschema.Package) bool {
	return pkg == nil || (pkg.Name == "" && pkg.Ecosystem == "" && pkg.Purl == "")
}

func validatePackage(pkg *osvschema.Package) (osvconstants.Ecosystem, error) {
	// If package is entirely empty, assume we are using a git-based ecosystem.
	if isPackageEmpty(pkg) {
		return ecosystemGit, nil
	}

	// Ecosystem must be set, and must be in the predefined set of ecosystems.
	// Note: the OSV schema allows for ecosystems to append information after a
	// colon (':') character.
	ecosystemFull := pkg.Ecosystem
	if ecosystemFull == "" {
		return "", fmt.Errorf("%w: package ecosystem is missing", ErrInvalidOSV)
	}
	e, _, _ := strings.Cut(ecosystemFull, ":")
	ecosystem := osvconstants.Ecosystem(e)
	if !slices.Contains(supportedEcosystems, ecosystem) {
		return "", fmt.Errorf("%w: package ecosystem %q is invalid", ErrInvalidOSV, ecosystem)
	}

	// Package name must be set.
	name := pkg.Name
	if name == "" {
		return "", fmt.Errorf("%w: package name is missing", ErrInvalidOSV)
	}
	// Package name must not contain special characters.
	if strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7F }) {
		return "", fmt.Errorf("%w: package name contains special characters", ErrInvalidOSV)
	}

	// If a PURL is set, ensure that it matches the package.
	if pkg.Purl != "" {
		if err := validatePURL(ecosystem, name, pkg.Purl); err != nil {
			return "", err
		}
	}

	return ecosystem, nil
}

// semverEcosystem is an allowlist indicating which ecosystems are allowed to
// have a range type of "SEMVER".
var semverEcosystem = map[osvconstants.Ecosystem]struct{}{
	osvconstants.EcosystemBitnami:  {},
	osvconstants.EcosystemCratesIO: {},
	osvconstants.EcosystemGo:       {},
	osvconstants.EcosystemHex:      {},
	osvconstants.EcosystemNPM:      {},
	osvconstants.EcosystemSwiftURL: {},
}

// validateRange ensures r conforms to the OSV Schema. This also ensures code
// that processes ranges can assume the data is well structured.
//
// See https://ossf.github.io/osv-schema/#affectedranges-field for details.
func validateRange(r *osvschema.Range, ecosystem osvconstants.Ecosystem) error {
	// The range type is required.
	if r == nil || r.Type == osvschema.Range_UNSPECIFIED {
		return fmt.Errorf("%w: range must have a type specified", ErrInvalidOSV)
	}
	// The range type can be either ECOSYSTEM, SEMVER or GIT.
	if !slices.Contains([]osvschema.Range_Type{osvschema.Range_ECOSYSTEM, osvschema.Range_SEMVER, osvschema.Range_GIT}, r.Type) {
		return fmt.Errorf("%w: range type %q is invalid", ErrInvalidOSV, r.Type.String())
	}
	// Ensure the ecosystem supports SEMVER if it is being used.
	if _, semverOK := semverEcosystem[ecosystem]; r.Type == osvschema.Range_SEMVER && !semverOK {
		return fmt.Errorf("%w: ecosystem %q does not support SEMVER ranges", ErrInvalidOSV, ecosystem)
	}
	// Ensure the type is GIT if ecosystem is empty.
	if ecosystem == ecosystemGit && r.Type != osvschema.Range_GIT {
		return fmt.Errorf("%w: GIT ranges must be used for git-based reports", ErrUnexpectedOSV)
	}
	// Validate the repo if the type is GIT.
	if r.Type == osvschema.Range_GIT {
		if r.Repo == "" {
			return fmt.Errorf("%w: GIT ranges must have a repository set", ErrUnexpectedOSV)
		}
		if _, err := gitname.Parse(r.Repo); err != nil {
			return fmt.Errorf("%w: invalid git repository: %w", ErrInvalidOSV, err)
		}
	}

	var hasFixed bool
	var hasLastAffected bool
	var hasIntroduced bool
	// Validate the events within the range as well.
	for _, e := range r.Events {
		var c int
		var val string
		allowZero := false
		if e.Fixed != "" {
			c++
			hasFixed = true
			val = e.Fixed
		}
		if e.Introduced != "" {
			c++
			hasIntroduced = true
			val = e.Introduced
			allowZero = true
		}
		if e.LastAffected != "" {
			c++
			hasLastAffected = true
			val = e.LastAffected
		}
		if e.Limit != "" {
			c++
			val = e.Limit
		}
		// Only a single type (either introduced, fixed, last_affected, limit)
		// is allowed in each event object.
		if c == 0 {
			return fmt.Errorf("%w: no event type is specified", ErrInvalidOSV)
		}
		if c > 1 {
			return fmt.Errorf("%w: more than one event type is specified", ErrInvalidOSV)
		}
		// Ensure the range contains a valid Git commit ID, if it is a Git range.
		if r.Type == osvschema.Range_GIT {
			if err := validateGitCommitID(val, allowZero); err != nil {
				return err
			}
		}
	}
	// Entries in the events array can contain either last_affected or fixed
	// events, but not both.
	if hasFixed && hasLastAffected {
		return fmt.Errorf("%w: contains both fixed and last affected", ErrInvalidOSV)
	}
	// There must be at least one introduced object in the events array.
	if !hasIntroduced {
		return fmt.Errorf("%w: no introduced event type", ErrInvalidOSV)
	}
	return nil
}

// validateGitCommitID ensures that candidate is a validly formatted git commit
// ID hash. Git commit IDs are a hex-encoded SHA1 or SHA256 hash.
func validateGitCommitID(candidate string, allowZero bool) error {
	if allowZero && candidate == "0" {
		return nil
	}
	sum, err := hex.DecodeString(candidate)
	if err != nil {
		return fmt.Errorf("%w: git hash %q is not valid hexadecimal: %w", ErrInvalidOSV, candidate, err)
	}
	if l := len(sum); l != sha256.Size && l != sha1.Size {
		return fmt.Errorf("%w: git hash %q has unexpected length", ErrInvalidOSV, candidate)
	}
	return nil
}

// validatePURL ensures that a PURL matches the supplied name and ecosystem.
func validatePURL(ecosystem osvconstants.Ecosystem, name, purl string) error {
	p, err := purlToPackage(purl)
	if err != nil {
		return fmt.Errorf("%w: failed parsing PURL %q: %w", ErrInvalidOSV, purl, err)
	}

	if p.Ecosystem != string(ecosystem) {
		return fmt.Errorf("%w: purl %q ecosystem %q does not match %q", ErrInvalidOSV, purl, p.Ecosystem, ecosystem)
	}

	if p.Name != name {
		return fmt.Errorf("%w: purl %q name %q does not match %q", ErrInvalidOSV, purl, p.Name, name)
	}

	return nil
}

// used like so: purlEcosystems[PkgURL.Type][PkgURL.Namespace]
// "*" means it should match any namespace string.
var purlEcosystems = map[string]map[string]osvconstants.Ecosystem{
	"apk":   {"alpine": osvconstants.EcosystemAlpine},
	"cargo": {"*": osvconstants.EcosystemCratesIO},
	"deb": {
		"debian": osvconstants.EcosystemDebian,
		"ubuntu": osvconstants.EcosystemUbuntu,
	},
	"hex":      {"*": osvconstants.EcosystemHex},
	"golang":   {"*": osvconstants.EcosystemGo},
	"maven":    {"*": osvconstants.EcosystemMaven},
	"nuget":    {"*": osvconstants.EcosystemNuGet},
	"npm":      {"*": osvconstants.EcosystemNPM},
	"composer": {"*": osvconstants.EcosystemPackagist},
	"generic":  {"*": osvconstants.EcosystemOSSFuzz},
	"pypi":     {"*": osvconstants.EcosystemPyPI},
	"gem":      {"*": osvconstants.EcosystemRubyGems},
}

func getPURLEcosystem(pkgURL packageurl.PackageURL) osvconstants.Ecosystem {
	ecoMap, ok := purlEcosystems[pkgURL.Type]
	if !ok {
		// We couldn't find a mapping between the PURL and OSV ecosystems.
		return osvconstants.Ecosystem("")
	}

	// An exact namespace match was found. This takes priority so return it
	// first.
	if ecosystem, ok := ecoMap[pkgURL.Namespace]; ok {
		return ecosystem
	}

	// The ecosystem has a wildcard namespace. The wildcard ecosystem will
	// always be returned if nothing better exists.
	if wildcardEco, hasWildcard := ecoMap["*"]; hasWildcard {
		return wildcardEco
	}

	// If we reached the end we don't have an OSV ecosystem for the given
	// PURL namespace.
	return osvconstants.Ecosystem("")
}

func purlToPackage(purl string) (*osvschema.Package, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return nil, err
	}
	ecosystem := getPURLEcosystem(parsedPURL)

	// PackageInfo expects the full namespace in the name for ecosystems that specify it.
	name := parsedPURL.Name
	if parsedPURL.Namespace != "" {
		switch ecosystem {
		case osvconstants.EcosystemMaven:
			// Maven uses : to separate namespace and package
			name = parsedPURL.Namespace + ":" + parsedPURL.Name
		case osvconstants.EcosystemDebian, osvconstants.EcosystemAlpine, osvconstants.EcosystemUbuntu:
			// Debian and Alpine repeats their namespace in PURL, so don't add it to the name
			name = parsedPURL.Name
		default:
			name = parsedPURL.Namespace + "/" + parsedPURL.Name
		}
	}

	return &osvschema.Package{
		Name:      name,
		Ecosystem: string(ecosystem),
	}, nil
}
