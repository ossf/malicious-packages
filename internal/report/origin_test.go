// Copyright 2025 Malicious Packages Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package report_test

import (
	"errors"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"

	"github.com/ossf/malicious-packages/internal/report"
)

func TestValidate_Origins_Valid(t *testing.T) {
	r := testReport(osvconstants.EcosystemPyPI, "example")
	r.AddOrigin("this-is-a-test-source-2", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() = %v; want no error", err)
	}
}

func TestValidate_Origins_ValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		source string
		sha256 string
	}{
		{
			name:   "source is empty",
			source: "",
			sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:   "source is invalid 1",
			source: "CAPITALS",
			sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:   "source is invalid 2",
			source: "spaces in source",
			sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:   "sha256 is empty",
			source: "valid-source",
			sha256: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := testReport(osvconstants.EcosystemPyPI, "example")
			r.AddOrigin(test.source, test.sha256)
			if err := r.Validate(); !errors.Is(err, report.ErrUnexpectedOSV) {
				t.Fatalf("Validate() = %v; want = %v", err, report.ErrUnexpectedOSV)
			}
		})
	}
}

func TestReport_HasOrigin(t *testing.T) {
	r := testReport(osvconstants.EcosystemPyPI, "example")
	r.AddOrigin("source-1", "deadbeef")

	if !r.HasOrigin("source-1", "deadbeef") {
		t.Errorf("HasOrigin(source-1, deadbeef) = false; want true")
	}
	if r.HasOrigin("source-1", "feedface") {
		t.Errorf("HasOrigin(source-1, feedface) = true; want false")
	}
	if r.HasOrigin("source-2", "deadbeef") {
		t.Errorf("HasOrigin(source-2, deadbeef) = true; want false")
	}
}

func TestReport_HasCommonOrigin(t *testing.T) {
	r1 := testReport(osvconstants.EcosystemPyPI, "example")
	r1.AddOrigin("source-1", "deadbeef")
	r1.AddOrigin("source-2", "12345678")

	r2 := testReport(osvconstants.EcosystemPyPI, "example")
	r2.AddOrigin("source-3", "abcdef00")

	if r1.HasCommonOrigin(r2) {
		t.Errorf("HasCommonOrigin() = true; want false")
	}

	r2.AddOrigin("source-1", "deadbeef")
	if !r1.HasCommonOrigin(r2) {
		t.Errorf("HasCommonOrigin() = false; want true")
	}
}
