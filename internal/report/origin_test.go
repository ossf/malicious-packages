package report_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ossf/malicious-packages/internal/report"
)

func TestOriginRefUnmarshalJSON(t *testing.T) {
	in := `{
		"source": "this-is-a-test-source-2",
		"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}`
	want := report.OriginRef{
		Source: "this-is-a-test-source-2",
		SHASum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	var got report.OriginRef
	err := got.UnmarshalJSON([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal() = %v; want nil", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unmarhsal() return unexpected result = %v, want %v", got, want)
	}
}

func TestOriginRefUnmarshalJSON_Error(t *testing.T) {
	var got report.OriginRef
	err := got.UnmarshalJSON([]byte("{"))

	if err == nil {
		t.Fatal("Unmarshal() = nil; want an error")
	}
}

func TestOriginRefUnmarshalJSON_ValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "source is empty",
			input: `{"source": "", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
		},
		{
			name:  "source is invalid 1",
			input: `{"source": "CAPITALS", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
		},
		{
			name:  "source is invalid 2",
			input: `{"source": "spaces in source", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
		},
		{
			name:  "sha256 is empty",
			input: `{"source": "valid-source", "sha256": ""}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var i report.OriginRef
			if err := i.UnmarshalJSON([]byte(test.input)); !errors.Is(err, report.ErrUnexpectedOSV) {
				t.Fatalf("Unmarshal() = %v; want = %v", err, report.ErrUnexpectedOSV)
			}
		})
	}
}
