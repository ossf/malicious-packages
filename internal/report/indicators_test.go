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
