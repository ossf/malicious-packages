package report

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxDomainLength = 255
	maxLabelLength  = 63
	maxNoteLength   = 512
	maxPathLength   = 1024
)

var (
	validDomainCharsRE = regexp.MustCompile("[a-zA-Z0-9_.-]+")
	sha256RE           = regexp.MustCompile("^[0-9a-f]{64}$")
	// TLSH digest: 70 hex characters, optionally prefixed with the "T1"
	// version marker emitted by newer TLSH implementations.
	tlshRE = regexp.MustCompile("^(?:T1)?[0-9A-Fa-f]{70}$")
)

// validFileSources enumerates the allowed values for FileIndicator.Source.
var validFileSources = map[string]bool{
	"package-archive": true,
	"downloaded":      true,
	"generated":       true,
}

type Indicators struct {
	Domains []string        `json:"domains"`
	IPs     []string        `json:"ips"`
	URLs    []string        `json:"urls"`
	Files   []FileIndicator `json:"files,omitempty"`
}

// FileIndicator describes a single file associated with a malicious package.
//
// It intentionally distinguishes files by their Source so that package
// artifacts (the published tarball/wheel, which may only ever be processed as a
// stream) can be recorded separately from files dropped or generated at run
// time (e.g. a second-stage payload downloaded from a C2, or content decoded
// from data embedded in the archive).
type FileIndicator struct {
	// Path is the file name (relative or absolute) as observed. Optional when
	// at least one digest is supplied (e.g. an in-memory second stage).
	Path string `json:"path,omitempty"`
	// Note is optional free text describing the file.
	Note string `json:"note,omitempty"`
	// Source records where the file came from: one of "package-archive",
	// "downloaded" or "generated". Optional.
	Source string `json:"source,omitempty"`
	// Digests holds one or more content hashes of the file.
	Digests *FileDigests `json:"digests,omitempty"`
}

// FileDigests holds content hashes for a FileIndicator, keyed by algorithm.
type FileDigests struct {
	// SHA256 is a lowercase hex-encoded SHA-256 digest (64 characters).
	SHA256 string `json:"sha256,omitempty"`
	// TLSH is a hex-encoded TLSH fuzzy hash, useful for clustering variants.
	TLSH string `json:"tlsh,omitempty"`
}

// UnmarshalJSON implements the json.Unmashaler interface.
//
// The implementation ensures that the indicators-of-compromise field (iocs) is
// populated correctly and common problems can be detected.
func (i *Indicators) UnmarshalJSON(b []byte) error {
	type raw Indicators
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}

	for _, d := range r.Domains {
		if !isDomainValid(d) {
			return fmt.Errorf("%w invalid domain '%s'", ErrUnexpectedOSV, d)
		}
	}

	for _, ip := range r.IPs {
		if strings.ContainsRune(ip, '/') {
			// Treat IP as a CIDR
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return fmt.Errorf("%w invalid CIDR '%s'", ErrUnexpectedOSV, ip)
			}
		} else {
			// Treat IP as a single address
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("%w invalid IP '%s'", ErrUnexpectedOSV, ip)
			}
		}
	}

	for _, u := range r.URLs {
		if _, err := url.Parse(u); err != nil {
			return fmt.Errorf("%w invalid URL '%s'", ErrUnexpectedOSV, u)
		}
	}

	for idx, f := range r.Files {
		if f.Source != "" && !validFileSources[f.Source] {
			return fmt.Errorf("%w invalid file source '%s'", ErrUnexpectedOSV, f.Source)
		}
		if len(f.Path) > maxPathLength {
			return fmt.Errorf("%w file path too long (%d > %d)", ErrUnexpectedOSV, len(f.Path), maxPathLength)
		}
		if len(f.Note) > maxNoteLength {
			return fmt.Errorf("%w file note too long (%d > %d)", ErrUnexpectedOSV, len(f.Note), maxNoteLength)
		}
		hasDigest := f.Digests != nil && (f.Digests.SHA256 != "" || f.Digests.TLSH != "")
		if f.Path == "" && !hasDigest {
			return fmt.Errorf("%w file[%d] must have a path or at least one digest", ErrUnexpectedOSV, idx)
		}
		if f.Digests != nil {
			if f.Digests.SHA256 != "" && !sha256RE.MatchString(f.Digests.SHA256) {
				return fmt.Errorf("%w invalid sha256 digest '%s'", ErrUnexpectedOSV, f.Digests.SHA256)
			}
			if f.Digests.TLSH != "" && !tlshRE.MatchString(f.Digests.TLSH) {
				return fmt.Errorf("%w invalid tlsh digest '%s'", ErrUnexpectedOSV, f.Digests.TLSH)
			}
		}
	}

	*i = Indicators(r)
	return nil
}

// isDomainValid checks if d is a valid domain name. This is a naive check and
// will permit some invalid domains. However, it will catch someone accidentally
// adding a URL or IP address as a domain.
func isDomainValid(d string) bool {
	if len(d) > maxDomainLength {
		return false
	}
	if validDomainCharsRE.FindString(d) != d {
		// Contains a invalid character.
		return false
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if len(l) > maxLabelLength {
			return false
		}
	}
	// Ensure IPs aren't domains.
	return net.ParseIP(d) == nil
}
