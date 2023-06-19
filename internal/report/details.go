package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	// detailHeader is the delimiter that sits between details provided by
	// contributors (above) and the details included from the origins (below).
	detailHeader = "\n##= Per source details. Do not edit below this line. =##\n"

	// detailSectionHeader preceeds each detail section indicating which source
	// and origin the details were included from.
	detailSectionHeader = "\n###= Source: %s (%s) =###\n"

	// detailSourceMatchIdx is the index in the match for detailSectionHeaderRE
	// for the source submatch.
	detailSourceMatchIdx = 1

	// detailSHASumMatchIdx is the index in the match for detailSectionHeaderRE
	// for the shasum submatch.
	detailSHASumMatchIdx = 2
)

// detailSectionHeaderRE is used to find the position of each section and
// extract the source information from it.
var detailSectionHeaderRE = regexp.MustCompile("(?s)\n###= Source: ([a-z0-9-]+) \\(([a-zA-Z0-9]+)\\) =###\n")

// RawDetails returns the raw, unparsed, details of the OSV report.
func (r *Report) RawDetails() string {
	return r.raw.Details
}

// ParseDetails attempts to separate the report details into its various parts.
//
// If it fails to parse the details an error will be returned, and user and
// sources will both be empty.
//
// On success user contains any user contributed details, and sources contains
// the detail provided by each unique source, where the key is the source ID.
func (r *Report) ParseDetails() (user string, sources map[*OriginRef]string, err error) {
	parts := strings.Split(r.raw.Details, detailHeader)
	if l := len(parts); l == 1 {
		// If parts has one entry then assume there are only user contributed details.
		user = strings.TrimSpace(r.raw.Details)
		return
	} else if l > 2 {
		// If we have more than two parts then somehow we have multiple headers.
		err = fmt.Errorf("%w: too many headers (%d)", ErrInvalidDetails, l-1)
		return
	}
	// If we reached here then we have both user contributed details, and
	// ingested source details.
	user = strings.TrimSpace(parts[0])
	sources = make(map[*OriginRef]string)
	if strings.TrimSpace(parts[1]) == "" {
		// It is possible that the header was added, but there are no source
		// details.
		return
	}
	matches := detailSectionHeaderRE.FindAllStringSubmatch(parts[1], -1)
	if matches == nil {
		return "", nil, fmt.Errorf("%w: invalid source details section", ErrInvalidDetails)
	}
	sourceDetails := detailSectionHeaderRE.Split(parts[1], -1)
	if len(sourceDetails) != len(matches)+1 {
		// The arrays always differ by one entry, if they don't, something has
		// gone very, very wrong.
		panic("regexp behaved differently for FindAllStringSubmatch and Split")
	}
	sourceDetails = sourceDetails[1:] // trim off the front as it sits before the first section.
	for idx, match := range matches {
		source := match[detailSourceMatchIdx]
		shasum := match[detailSHASumMatchIdx]
		detail := strings.TrimSpace(sourceDetails[idx])
		o := r.getOrigin(source, shasum)
		if o == nil {
			return "", nil, fmt.Errorf("%w: source detail with missing origin %s %s", ErrInvalidDetails, source, shasum)
		}
		sources[o] = detail
	}
	return
}

// SetDetails constructs and stores the OSV details based on any user contributed
// details and any origin details for a source.
//
// If a source has multiple origins present, the origin for the same source with
// the longest detail will be chosen based on the assumption that the longer
// detail has more information in it.
func (r *Report) SetDetails(user string, sourceDetailsSet ...map[*OriginRef]string) {
	res := ""
	if user != "" {
		res = strings.TrimSpace(user) + "\n"
	}
	res = res + detailHeader
	bestOrigins := make(map[string]*OriginRef)
	var sources []string
	detailMap := make(map[*OriginRef]string)
	for _, sourceDetails := range sourceDetailsSet {
		for o, d := range sourceDetails {
			if strings.TrimSpace(d) == "" {
				// Ignore empty strings.
				continue
			}
			detailMap[o] = d
			// Find the existing best origin for the same source as our current origin.
			existing := bestOrigins[o.Source]
			if existing == nil {
				// No existing best origin, so the current origin is the best.
				bestOrigins[o.Source] = o
				sources = append(sources, o.Source)
				continue
			}
			// Grab the existing best description and only replace it if the current
			// one is longer.
			bestD := detailMap[existing]
			if len(d) > len(bestD) {
				bestOrigins[o.Source] = o
			}
		}
	}
	// Ensure the sources are in a stable order.
	sort.StringSlice(sources).Sort()
	for _, s := range sources {
		o := bestOrigins[s]
		d := detailMap[o]
		res = res + fmt.Sprintf(detailSectionHeader, o.Source, o.SHASum) + strings.TrimSpace(d) + "\n"
	}
	// Assign!
	r.raw.Details = res
}
