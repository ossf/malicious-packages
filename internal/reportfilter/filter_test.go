// Copyright 2024 Malicious Packages Authors
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

package reportfilter_test

import (
	"reflect"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/ossf/malicious-packages/internal/reportfilter"
)

func TestNew_PatternError(t *testing.T) {
	_, err := reportfilter.New("aliases", "(")
	if err == nil {
		t.Fatal("New() = nil, want an error")
	}
}

func TestNew_UnsupportedFieldError(t *testing.T) {
	_, err := reportfilter.New("not_a_valid_field", ".*")
	if err == nil {
		t.Fatal("New() = nil, want an error")
	}
}

func TestRemoveFilter(t *testing.T) {
	vuln := &models.Vulnerability{
		ID: "MAL-0123-45678",
		Aliases: []string{
			"A-1",
			"A-2",
			"B-1",
			"C-99",
		},
		Related: []string{
			"A-2023-123",
			"A-2024-123",
			"B-2024-456",
			"C-2025-789",
		},
	}
	want := &models.Vulnerability{
		ID: "MAL-0123-45678",
		Aliases: []string{
			"B-1",
		},
		Related: []string{
			"A-2023-123",
			"C-2025-789",
		},
	}
	must := func(f reportfilter.Filter, err error) reportfilter.Filter {
		if err != nil {
			t.Fatalf("New() = error, want no error")
		}
		return f
	}
	filters := reportfilter.Filters{
		must(reportfilter.New("aliases", "^A-")),
		must(reportfilter.New("aliases", "-99$")),
		must(reportfilter.New("related", "-2024-")),
	}
	filters.Apply(vuln)
	if !reflect.DeepEqual(vuln, want) {
		t.Fatalf("Apply() failed: got = %v, want = %v", vuln, want)
	}
}
