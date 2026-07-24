package report_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ossf/malicious-packages/internal/report"
)

func TestIndicatorsUnmarshalJSON(t *testing.T) {
	in := `{
		"domains": ["example", "example.com", "this.is.an.example.com", "_service.at.example.com", "foo-bar.example.com", "g.co"],
		"ips": ["127.0.0.1", "127.0.0.0/24", "2001:db8:a0b:12f0::1", "2001:db8:a0b:12f0::1/32"],
		"urls": ["https://example.com", "emailto:person@example.com", "authority:"]
	}`
	want := report.Indicators{
		Domains: []string{"example", "example.com", "this.is.an.example.com", "_service.at.example.com", "foo-bar.example.com", "g.co"},
		IPs:     []string{"127.0.0.1", "127.0.0.0/24", "2001:db8:a0b:12f0::1", "2001:db8:a0b:12f0::1/32"},
		URLs:    []string{"https://example.com", "emailto:person@example.com", "authority:"},
	}

	var got report.Indicators
	err := got.UnmarshalJSON([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal() = %v; want nil", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unmarhsal() return unexpected result = %v, want %v", got, want)
	}
}

func TestIndicatorsUnmarshalJSON_Error(t *testing.T) {
	var got report.Indicators
	err := got.UnmarshalJSON([]byte("{"))

	if err == nil {
		t.Fatal("Unmarshal() = nil; want an error")
	}
}

func TestIndicatorsUnmarshalJSON_ValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "domain in ip",
			input: `{"ips": ["example.com"]}`,
		},
		{
			name:  "url in ip",
			input: `{"ips": ["https://example.com"]}`,
		},
		{
			name:  "invalid ip 1",
			input: `{"ips": ["127.0.1"]}`,
		},
		{
			name:  "invalid ip 2",
			input: `{"ips": ["127.0.0.0.1"]}`,
		},
		{
			name:  "invalid cidr 1",
			input: `{"ips": ["127.0.0.1//"]}`,
		},
		{
			name:  "invalid cidr 2",
			input: `{"ips": ["127.0.0.1/33"]}`,
		},
		{
			name:  "url in domain 1",
			input: `{"domains": ["https://example.com/"]}`,
		},
		{
			name:  "url in domain 2",
			input: `{"domains": ["example.com/path"]}`,
		},
		{
			name:  "ip in domain",
			input: `{"domains": ["127.0.0.1"]}`,
		},
		{
			name:  "invalid domain 1",
			input: `{"domains": ["💩"]}`,
		},
		{
			name:  "invalid domain 3",
			input: `{"domains": ["this.is.a.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.long.domain.example.com"]}`,
		},
		{
			name:  "invalid domain 4",
			input: `{"domains": ["this-is-a-really-really-really-really-really-really-really-really-really-long-label.example.com"]}`,
		},
		{
			name:  "invalid url",
			input: `{"urls": ["://domain"]}`,
		},
		{
			name:  "invalid file source",
			input: `{"files": [{"paths": ["x.js"], "source": "email"}]}`,
		},
		{
			name:  "invalid file sha256",
			input: `{"files": [{"paths": ["x.js"], "digests": {"sha256": "not-a-hash"}}]}`,
		},
		{
			name:  "invalid file md5",
			input: `{"files": [{"paths": ["x.js"], "digests": {"md5": "zz"}}]}`,
		},
		{
			name:  "invalid file tlsh",
			input: `{"files": [{"paths": ["x.js"], "digests": {"tlsh": "xyz"}}]}`,
		},
		{
			name:  "invalid file ssdeep",
			input: `{"files": [{"paths": ["x.js"], "digests": {"ssdeep": "notssdeep"}}]}`,
		},
		{
			name:  "empty file entry",
			input: `{"files": [{"note": "no path and no digest"}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var i report.Indicators
			if err := i.UnmarshalJSON([]byte(test.input)); !errors.Is(err, report.ErrUnexpectedOSV) {
				t.Fatalf("Unmarshal() = %v; want = %v", err, report.ErrUnexpectedOSV)
			}
		})
	}
}

func TestIndicatorsUnmarshalJSON_Files(t *testing.T) {
	// The sha256 in the first file and the tlsh in the second are supplied in
	// UPPER-case to exercise case-insensitive validation + lowercase normalization.
	in := `{
		"files": [
			{
				"paths": ["package/postinstall.js"],
				"source": "package-archive",
				"digests": {"sha256": "BD13913906ED463642719633F36F04CF10AE6F9C9360FCDE842F8B6B1DAF0B02"}
			},
			{
				"paths": ["/tmp/stage2.bin", "/var/tmp/stage2.bin"],
				"note": "second stage dropped from a C2",
				"source": "dropped",
				"digests": {
					"md5": "d41d8cd98f00b204e9800998ecf8427e",
					"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
					"sha256": "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
					"tlsh": "T10123456789012345678901234567890123456789012345678901234567890123456789",
					"ssdeep": "12:AbCd+/12:XyZ"
				}
			},
			{
				"source": "in-memory",
				"note": "decoded payload that never hit disk",
				"digests": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
			}
		]
	}`
	want := report.Indicators{
		Files: []report.FileIndicator{
			{
				Paths:   []string{"package/postinstall.js"},
				Source:  "package-archive",
				Digests: &report.FileDigests{SHA256: "bd13913906ed463642719633f36f04cf10ae6f9c9360fcde842f8b6b1daf0b02"},
			},
			{
				Paths:  []string{"/tmp/stage2.bin", "/var/tmp/stage2.bin"},
				Note:   "second stage dropped from a C2",
				Source: "dropped",
				Digests: &report.FileDigests{
					MD5:    "d41d8cd98f00b204e9800998ecf8427e",
					SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
					SHA256: "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
					TLSH:   "t10123456789012345678901234567890123456789012345678901234567890123456789",
					SSDEEP: "12:AbCd+/12:XyZ",
				},
			},
			{
				Source:  "in-memory",
				Note:    "decoded payload that never hit disk",
				Digests: &report.FileDigests{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
			},
		},
	}

	var got report.Indicators
	if err := got.UnmarshalJSON([]byte(in)); err != nil {
		t.Fatalf("Unmarshal() = %v; want nil", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unmarshal() = %v, want %v", got, want)
	}
}
