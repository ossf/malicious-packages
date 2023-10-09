package report

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
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
	ecosystem := string(v.Affected[0].Package.Ecosystem)
	if ecosystem == "" {
		return fmt.Errorf("%w: package ecosystem is missing", ErrInvalidOSV)
	}
	if e, _, _ := strings.Cut(ecosystem, ":"); !slices.Contains(models.Ecosystems, models.Ecosystem(e)) {
		return fmt.Errorf("%w: package ecosystem '%s' is invalid", ErrInvalidOSV, e)
	}

	// Package name must be set.
	if v.Affected[0].Package.Name == "" {
		return fmt.Errorf("%w: package name is missing", ErrInvalidOSV)
	}

	// Validate the ranges are correct.
	for _, rng := range v.Affected[0].Ranges {
		if err := validateRange(rng); err != nil {
			return err
		}
	}

	return nil
}

// validateRange ensures r conforms to the OSV Schema. This also ensures code
// that processes ranges can assume the data is well structured.
//
// See https://ossf.github.io/osv-schema/#affectedranges-field for details.
func validateRange(r models.Range) error {
	// The range type is required.
	if r.Type == "" {
		return fmt.Errorf("%w: range must have a type specified", ErrInvalidOSV)
	}
	// The range type can be either ECOSYSTEM, SEMVER or GIT.
	if !slices.Contains([]models.RangeType{models.RangeEcosystem, models.RangeSemVer, models.RangeGit}, r.Type) {
		return fmt.Errorf("%w: range type '%s' is invalid", ErrInvalidOSV, r.Type)
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
