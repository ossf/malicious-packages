package report

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
)

var ErrMergeFailure = errors.New("merge failure")

func (r *Report) Merge(other *Report) error {
	if r.Ecosystem != other.Ecosystem {
		return fmt.Errorf("%w: attempting to merge report from different ecosystem (%s != %s)", ErrMergeFailure, r.Ecosystem, other.Ecosystem)
	}
	if r.Name != other.Name {
		return fmt.Errorf("%w: attempting to merge report with different name (%s != %s)", ErrMergeFailure, r.Name, other.Name)
	}
	// Merging must be done before ID assignment.
	if other.raw.ID != "" {
		return fmt.Errorf("%w: attempting to merge report after ID assigned", ErrMergeFailure)
	}
	// Bail out if the sets of origins intersect.
	if r.HasCommonOrigin(other) {
		return fmt.Errorf("%w: reports contain common origins", ErrMergeFailure)
	}
	// Ensure the other report is normalized as well.
	if err := other.Normalize(); err != nil {
		return fmt.Errorf("failed to normalize other report: %w", err)
	}

	r.raw.Affected[0].Ranges = append(r.raw.Affected[0].Ranges, other.raw.Affected[0].Ranges...)
	r.raw.Affected[0].Versions = mergeSlices(r.raw.Affected[0].Versions, other.raw.Affected[0].Versions)
	r.raw.Affected[0].Severity = nil
	r.raw.Affected[0].DatabaseSpecific = combineDatabaseSpecific(r.raw.Affected[0].DatabaseSpecific, other.raw.Affected[0].DatabaseSpecific)
	r.raw.Affected[0].EcosystemSpecific = nil

	// Combine complex types
	r.raw.Credits = combineCredits(r.raw.Credits, other.raw.Credits)
	r.raw.References = mergeSlices(r.raw.References, other.raw.References)
	r.raw.Aliases = mergeSlices(r.raw.Aliases, other.raw.Aliases)
	// r.raw.Related = mergeSlices(r.raw.Related, other.raw.Related)  // uncomment when osv-scanner is released
	r.raw.Severity = nil

	// Description merging.
	userDetails, sourceDetails, err := r.ParseDetails()
	if err != nil {
		return fmt.Errorf("%w: parsing details: %w", ErrMergeFailure, err)
	}
	otherUserDetails, otherSourceDetails, err := other.ParseDetails()
	if err != nil {
		// NOTE: This should never occur, because Normalize has been called.
		panic(fmt.Sprintf("Error calling ParseDetails on other after Normalize: %v", err))
	}
	if otherUserDetails != "" && len(otherSourceDetails) > 0 {
		// Either the other report is user submitted and being merged with other
		// new reports, or the other report is ingested with an origin. It can't
		// be both.
		// NOTE: This should never occur, because Normalize has been called.
		panic("Error inconsistent other ParseDetails after Normalize")
	}
	if otherUserDetails != "" && userDetails != "" {
		// If both reports have user contributed details throw an error. The user
		// contributed details should be on the existing report.
		return fmt.Errorf("%w: reports both have user details", ErrMergeFailure)
	}
	if userDetails == "" {
		userDetails = otherUserDetails
	}
	r.SetDetails(userDetails, sourceDetails, otherSourceDetails)

	// Update modified to reflect the merge time.
	r.raw.Modified = time.Now().UTC()

	// Use the earliest published time, otherwise use now (from modified) if unset.
	if r.raw.Published.IsZero() && other.raw.Published.IsZero() {
		r.raw.Published = r.raw.Modified
	} else if r.raw.Published.IsZero() || (!other.raw.Published.IsZero() && other.raw.Published.Before(r.raw.Published)) {
		r.raw.Published = other.raw.Published
	}

	// Merge all the database specific data
	r.origins = append(r.origins, other.origins...)
	r.raw.DatabaseSpecific = combineDatabaseSpecific(r.raw.DatabaseSpecific, other.raw.DatabaseSpecific)

	return nil
}

func combineCredits(creditSets ...[]models.Credit) []models.Credit {
	credits := make(map[struct {
		t models.CreditType
		n string
	}]models.Credit)
	for _, cs := range creditSets {
		for _, c := range cs {
			k := struct {
				t models.CreditType
				n string
			}{t: c.Type, n: c.Name}
			if existing, ok := credits[k]; ok {
				// Merge contact lists if we see the same contact.
				c.Contact = mergeSlices(existing.Contact, c.Contact)
			}
			credits[k] = c
		}
	}
	var creditList []models.Credit
	for _, c := range credits {
		creditList = append(creditList, c)
	}
	// Sort to make the credit ordering stable.
	slices.SortFunc(creditList, func(a, b models.Credit) bool {
		if a.Name < b.Name {
			return true
		} else if a.Name == b.Name {
			return a.Type < b.Type
		}
		return false
	})
	return creditList
}

func mergeSlices[K comparable](ss ...[]K) []K {
	seen := make(map[K]struct{})
	var res []K
	for _, s := range ss {
		for _, e := range s {
			if _, ok := seen[e]; ok {
				continue
			}
			seen[e] = struct{}{}
			res = append(res, e)
		}
	}
	return res
}

// combineDatabaseSpecific merge general database_specific OSV entries.
//
// The following rules are used to determine how the merge works:
// - sources *must* have keys unique to that source.
// - values must not be scalars. they must be arrays or objects.
// - values that are arrays are concatenated together, duplicates will be preserved.
// - values that are objects are merged, keys should be unique, but if they are the same the first key seen will retain its value.
func combineDatabaseSpecific(objs ...map[string]any) map[string]any {
	if len(objs) == 0 {
		return nil
	}
	res := make(map[string]any)
	for _, obj := range objs {
		for k, v := range obj {
			switch v.(type) {
			case map[string]any:
			case []any:
			default:
				// Skip because there should be no scalars after normalization.
				continue
			}
			if _, ok := res[k]; !ok {
				// Key doesn't exist, so add it immediately.
				res[k] = v
				continue
			}
			switch existing := res[k].(type) {
			case map[string]any:
				anyMap := v.(map[string]any)
				for innerK, innerV := range anyMap {
					// Only merge keys that don't already exist.
					if _, ok := existing[innerK]; !ok {
						existing[innerK] = innerV
					}
				}
			case []any:
				anyList := v.([]any)
				res[k] = append(existing, anyList...)
			}
		}
	}
	return res
}
