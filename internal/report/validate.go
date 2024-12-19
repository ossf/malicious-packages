package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

// ValidateVuln ensures that v conforms to the the OSV Schema, and to the
// specific constraints expected by the repository.
func ValidateVuln(v *models.Vulnerability) error {
	// A malicious packages vuln must have one and only one Affected entry.
	if len(v.Affected) == 0 {
		return fmt.Errorf("%w: no affected packages listed", ErrInvalidOSV)
	}
	if len(v.Affected) > 1 {
		return fmt.Errorf("%w: multiple affected entries", ErrUnexpectedOSV)
	}

	// Ecosystem must be set, and must be in the predefined set of ecosystems.
	// Note: the OSV schema allows for ecosystems to append information after a
	// colon (':') character.
	ecosystemFull := string(v.Affected[0].Package.Ecosystem)
	if ecosystemFull == "" {
		return fmt.Errorf("%w: package ecosystem is missing", ErrInvalidOSV)
	}
	e, _, _ := strings.Cut(ecosystemFull, ":")
	ecosystem := models.Ecosystem(e)
	if !slices.Contains(models.Ecosystems, ecosystem) {
		return fmt.Errorf("%w: package ecosystem %q is invalid", ErrInvalidOSV, ecosystem)
	}

	// Package name must be set.
	name := v.Affected[0].Package.Name
	if name == "" {
		return fmt.Errorf("%w: package name is missing", ErrInvalidOSV)
	}

	// If a PURL is set, ensure that it matches the package.
	if v.Affected[0].Package.Purl != "" {
		if err := validatePURL(ecosystem, name, v.Affected[0].Package.Purl); err != nil {
			return err
		}
	}

	// Validate the ranges are correct.
	for _, rng := range v.Affected[0].Ranges {
		if err := validateRange(rng, ecosystem); err != nil {
			return err
		}
	}

	return nil
}

// semverEcosystem is an allowlist indicating which ecosystems are allowed to
// have a range type of "SEMVER".
//
// The source of this list is:
// https://github.com/google/osv.dev/blob/master/osv/ecosystems/_ecosystems.py
//
// Unfortunately this information is not specified in the OSV schema, or
// enforced by the OSV API presently.
var semverEcosystem = map[models.Ecosystem]struct{}{
	models.EcosystemBitnami:  {},
	models.EcosystemCratesIO: {},
	models.EcosystemGo:       {},
	models.EcosystemHex:      {},
	models.EcosystemNPM:      {},
	models.EcosystemSwiftURL: {},
}

// validateRange ensures r conforms to the OSV Schema. This also ensures code
// that processes ranges can assume the data is well structured.
//
// See https://ossf.github.io/osv-schema/#affectedranges-field for details.
func validateRange(r models.Range, ecosystem models.Ecosystem) error {
	// The range type is required.
	if r.Type == "" {
		return fmt.Errorf("%w: range must have a type specified", ErrInvalidOSV)
	}
	// The range type can be either ECOSYSTEM, SEMVER or GIT.
	if !slices.Contains([]models.RangeType{models.RangeEcosystem, models.RangeSemVer, models.RangeGit}, r.Type) {
		return fmt.Errorf("%w: range type %q is invalid", ErrInvalidOSV, r.Type)
	}
	// Ensure the ecosystem supports SEMVER if it is being used.
	if _, semverOK := semverEcosystem[ecosystem]; r.Type == models.RangeSemVer && !semverOK {
		return fmt.Errorf("%w: ecosystem %q does not support SEMVER ranges", ErrInvalidOSV, ecosystem)
	}

	var hasFixed bool
	var hasLastAffected bool
	var hasIntroduced bool
	// Validate the events within the range as well.
	for _, e := range r.Events {
		var c int
		if e.Fixed != "" {
			c++
			hasFixed = true
		}
		if e.Introduced != "" {
			c++
			hasIntroduced = true
		}
		if e.LastAffected != "" {
			c++
			hasLastAffected = true
		}
		if e.Limit != "" {
			c++
		}
		// Only a single type (either introduced, fixed, last_affected, limit)
		// is allowed in each event object.
		if c == 0 {
			return fmt.Errorf("%w: no event type is specified", ErrInvalidOSV)
		}
		if c > 1 {
			return fmt.Errorf("%w: more than one event type is specified", ErrInvalidOSV)
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

// validatePURL ensures that a PURL matches the supplied name and ecosystem.
func validatePURL(ecosystem models.Ecosystem, name, purl string) error {
	p, err := models.PURLToPackage(purl)
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
