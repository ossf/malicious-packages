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
)

var validDomainCharsRE = regexp.MustCompile("[a-zA-Z0-9_.-]+")

type Indicators struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	URLs    []string `json:"urls"`
}

// UnmarshalJSON implements the json.Unmashaler interface.
//
// The implementation ensures that the resulting parsed data is valid for the
// purposes of tracking malicious packages.
//
// The implementation also extracts the database specific data tracking the
// origins the report.
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
