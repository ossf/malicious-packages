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
			input: `{"files": [{"path": "x.js", "source": "email"}]}`,
		},
		{
			name:  "invalid file sha256",
			input: `{"files": [{"path": "x.js", "digests": {"sha256": "not-a-hash"}}]}`,
		},
		{
			name:  "invalid file tlsh",
			input: `{"files": [{"path": "x.js", "digests": {"tlsh": "xyz"}}]}`,
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
	in := `{
		"files": [
			{
				"path": "package/postinstall.js",
				"source": "package-archive",
				"digests": {"sha256": "bd13913906ed463642719633f36f04cf10ae6f9c9360fcde842f8b6b1daf0b02"}
			},
			{
				"path": "/tmp/stage2.bin",
				"note": "second stage fetched from C2",
				"source": "downloaded",
				"digests": {
					"sha256": "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
					"tlsh": "T10123456789012345678901234567890123456789012345678901234567890123456789"
				}
			}
		]
	}`
	want := report.Indicators{
		Files: []report.FileIndicator{
			{
				Path:    "package/postinstall.js",
				Source:  "package-archive",
				Digests: &report.FileDigests{SHA256: "bd13913906ed463642719633f36f04cf10ae6f9c9360fcde842f8b6b1daf0b02"},
			},
			{
				Path:   "/tmp/stage2.bin",
				Note:   "second stage fetched from C2",
				Source: "downloaded",
				Digests: &report.FileDigests{
					SHA256: "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
					TLSH:   "T10123456789012345678901234567890123456789012345678901234567890123456789",
				},
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
