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
	// Hex digests are validated case-insensitively and normalized to lowercase.
	md5RE    = regexp.MustCompile("^(?i)[0-9a-f]{32}$")
	sha1RE   = regexp.MustCompile("^(?i)[0-9a-f]{40}$")
	sha256RE = regexp.MustCompile("^(?i)[0-9a-f]{64}$")
	// TLSH: 70 hex characters, optionally prefixed with the "T1" version marker
	// emitted by newer TLSH implementations.
	tlshRE = regexp.MustCompile("^(?i)(?:t1)?[0-9a-f]{70}$")
	// ssdeep: "<blocksize>:<hash>:<hash>" (base64-ish; case-sensitive, not hex).
	ssdeepRE = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$`)
)

// validFileSources enumerates the allowed values for FileIndicator.Source.
var validFileSources = map[string]bool{
	"package-archive": true,
	"dropped":         true,
	"in-memory":       true,
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
// stream) are recorded separately from other files associated with the malware,
// such as a second stage dropped at run time or a payload that only ever lived
// in memory.
type FileIndicator struct {
	// Paths lists the file names (relative or absolute) at which the file was
	// observed — the same content can appear in several places. Optional for a
	// file that never hit disk (Source "in-memory"), which is identified by its
	// digest alone.
	Paths []string `json:"paths,omitempty"`
	// Note is optional free text describing the file.
	Note string `json:"note,omitempty"`
	// Source records where the file came from: one of "package-archive",
	// "dropped" or "in-memory". Optional.
	Source string `json:"source,omitempty"`
	// Digests holds one or more content hashes of the file.
	Digests *FileDigests `json:"digests,omitempty"`
}

// FileDigests holds content hashes for a FileIndicator, keyed by algorithm.
// sha256 is preferred and recommended at a minimum. Hex digests may be supplied
// in any case; they are normalized to lowercase.
type FileDigests struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	TLSH   string `json:"tlsh,omitempty"`
	SSDEEP string `json:"ssdeep,omitempty"`
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

	for idx := range r.Files {
		f := &r.Files[idx] // pointer so digest normalization persists
		if f.Source != "" && !validFileSources[f.Source] {
			return fmt.Errorf("%w invalid file source '%s'", ErrUnexpectedOSV, f.Source)
		}
		for _, p := range f.Paths {
			if len(p) > maxPathLength {
				return fmt.Errorf("%w file path too long (%d > %d)", ErrUnexpectedOSV, len(p), maxPathLength)
			}
		}
		if len(f.Note) > maxNoteLength {
			return fmt.Errorf("%w file note too long (%d > %d)", ErrUnexpectedOSV, len(f.Note), maxNoteLength)
		}
		d := f.Digests
		hasDigest := d != nil && (d.MD5 != "" || d.SHA1 != "" || d.SHA256 != "" || d.TLSH != "" || d.SSDEEP != "")
		if len(f.Paths) == 0 && !hasDigest {
			return fmt.Errorf("%w file[%d] must have at least one path or one digest", ErrUnexpectedOSV, idx)
		}
		if d != nil {
			// Hex digests are validated case-insensitively and normalized to
			// lowercase; ssdeep is case-sensitive (base64-ish) so it is left as-is.
			if d.MD5 != "" {
				if !md5RE.MatchString(d.MD5) {
					return fmt.Errorf("%w invalid md5 digest '%s'", ErrUnexpectedOSV, d.MD5)
				}
				d.MD5 = strings.ToLower(d.MD5)
			}
			if d.SHA1 != "" {
				if !sha1RE.MatchString(d.SHA1) {
					return fmt.Errorf("%w invalid sha1 digest '%s'", ErrUnexpectedOSV, d.SHA1)
				}
				d.SHA1 = strings.ToLower(d.SHA1)
			}
			if d.SHA256 != "" {
				if !sha256RE.MatchString(d.SHA256) {
					return fmt.Errorf("%w invalid sha256 digest '%s'", ErrUnexpectedOSV, d.SHA256)
				}
				d.SHA256 = strings.ToLower(d.SHA256)
			}
			if d.TLSH != "" {
				if !tlshRE.MatchString(d.TLSH) {
					return fmt.Errorf("%w invalid tlsh digest '%s'", ErrUnexpectedOSV, d.TLSH)
				}
				d.TLSH = strings.ToLower(d.TLSH)
			}
			if d.SSDEEP != "" && !ssdeepRE.MatchString(d.SSDEEP) {
				return fmt.Errorf("%w invalid ssdeep digest '%s'", ErrUnexpectedOSV, d.SSDEEP)
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
