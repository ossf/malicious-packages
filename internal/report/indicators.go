package report

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	mppb "github.com/ossf/malicious-packages/proto"
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

func validateIOCs(iocs *mppb.Indicators) error {
	for _, d := range iocs.GetDomains() {
		if !isDomainValid(d) {
			return fmt.Errorf("%w invalid domain '%s'", ErrUnexpectedOSV, d)
		}
	}

	for _, ip := range iocs.GetIps() {
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

	for _, u := range iocs.GetUrls() {
		if _, err := url.Parse(u); err != nil {
			return fmt.Errorf("%w invalid URL '%s'", ErrUnexpectedOSV, u)
		}
	}

	for i, file := range iocs.GetFiles() {
		if err := validateFile(i, file); err != nil {
			return err
		}
	}
	return nil
}

// validateFile checks one FileIndicator (source, path lengths, note length, and
// the "at least one path or digest" rule) and normalizes its hex digests. Split
// out of UnmarshalJSON to keep that method's complexity low.
func validateFile(idx int, f *mppb.Indicators_File) error {
	for _, p := range f.GetPaths() {
		if len(p) > maxPathLength {
			return fmt.Errorf("%w file path too long (%d > %d)", ErrUnexpectedOSV, len(p), maxPathLength)
		}
	}
	if len(f.Note) > maxNoteLength {
		return fmt.Errorf("%w file note too long (%d > %d)", ErrUnexpectedOSV, len(f.Note), maxNoteLength)
	}
	d := f.GetDigests()
	// Require at least one exact content digests. Fuzzy digests are entirely optional.
	hasDigest := d != nil && (d.GetMd5() != "" || d.GetSha1() != "" || d.GetSha256() != "")
	if len(f.GetPaths()) == 0 && !hasDigest {
		return fmt.Errorf("%w file[%d] must have at least one path or one digest", ErrUnexpectedOSV, idx)
	}
	return validateDigests(d)
}

// validateDigests validates each present digest, then normalizes the hex ones to
// lowercase in place. Validation and normalization are kept as separate steps.
// ssdeep is case-sensitive (base64-ish) and left as-is.
func validateDigests(d *mppb.Indicators_File_Digests) error {
	if d == nil {
		return nil
	}
	// Validate (no mutation).
	if err := validateHex("md5", d.GetMd5(), md5RE); err != nil {
		return err
	}
	if err := validateHex("sha1", d.GetSha1(), sha1RE); err != nil {
		return err
	}
	if err := validateHex("sha256", d.GetSha256(), sha256RE); err != nil {
		return err
	}
	if err := validateHex("tlsh", d.GetTlsh(), tlshRE); err != nil {
		return err
	}
	if ssdeep := d.GetSsdeep(); ssdeep != "" && !ssdeepRE.MatchString(ssdeep) {
		return fmt.Errorf("%w invalid ssdeep digest '%s'", ErrUnexpectedOSV, ssdeep)
	}
	// Normalize the hex digests to lowercase (ssdeep is case-sensitive).
	// TODO: these are currently ineffective and should be moved to a normalize
	// routine and only update if Has*() is true.
	d.SetMd5(strings.ToLower(d.GetMd5()))
	d.SetSha1(strings.ToLower(d.GetSha1()))
	d.SetSha256(strings.ToLower(d.GetSha256()))
	d.SetTlsh(strings.ToLower(d.GetTlsh()))
	return nil
}

// validateHex checks that a hex digest matches its expected shape
// (case-insensitive). An empty value is allowed. It does not mutate the value —
// lowercasing is done separately by the caller.
func validateHex(name, val string, re *regexp.Regexp) error {
	if val == "" {
		return nil
	}
	if !re.MatchString(val) {
		return fmt.Errorf("%w invalid %s digest '%s'", ErrUnexpectedOSV, name, val)
	}
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
