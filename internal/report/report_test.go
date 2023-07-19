// Copyright 2023 Malicious Packages Authors
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
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/ossf/malicious-packages/internal/report"
)

func testReport(ecosystem models.Ecosystem, name string) *report.Report {
	rJSON := `{ "schema_version": "1.5.0", "summary": "test report", "affected": [{"package":{"ecosystem": "%s", "name": "%s"}}]}`
	r, err := report.ReadJSON(bytes.NewBufferString(fmt.Sprintf(rJSON, ecosystem, name)))
	if err != nil {
		panic(err)
	}
	return r
}

func TestPath(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      string
	}{
		{
			name:      "github.com/ossf/malicious-packages/cmd/ingest",
			ecosystem: "Go",
			want:      "go/github.com/ossf/malicious-packages/cmd/ingest",
		},
		{
			name:      "ThIs-is-A-Package",
			ecosystem: "Github Action",
			want:      "github-action/this-is-a-package",
		},
		{
			name:      "././../../this/is-a_problematic/example/../.././",
			ecosystem: ".//.././.../ecosystem/../..././../",
			want:      "../this",
		},
	}
	for _, test := range tests {
		t.Run(test.ecosystem+" "+test.name, func(t *testing.T) {
			r := &report.Report{Name: test.name, Ecosystem: test.ecosystem}
			if got := r.Path(); got != test.want {
				t.Errorf("Dir() = %v; want %v", got, test.want)
			}
		})
	}
}

func TestNormalize_WithID(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().ID = "MAL-1234-5678"

	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v; want no error", err)
	}
}

func TestNormalize_Summary(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")

	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v; want no error", err)
	}

	want := "Malicious code in example (RubyGems)"
	if got := r.Vuln().Summary; got != want {
		t.Errorf("Summary = %v; want %v", got, want)
	}
}

func TestNormalize_TooManyOrigins(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.AddOrigin("test-origin", "deadbeef")
	r.AddOrigin("another-test-origin", "00000000")

	if err := r.Normalize(); err == nil || !errors.Is(err, report.ErrNormalizing) {
		t.Fatalf("Normalize() = %v; want %v", err, report.ErrNormalizing)
	}
}

func TestNormalize_DetailHeaderPresent(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.SetDetails("user")

	if err := r.Normalize(); err == nil || !errors.Is(err, report.ErrNormalizing) {
		t.Fatalf("Normalize() = %v; want %v", err, report.ErrNormalizing)
	}
}

func TestNormalize_DatabaseSpecificStrip(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().DatabaseSpecific = map[string]any{
		"object":    map[string]any{"a": "b"},
		"array":     []any{"a", 1},
		"scalar":    42,
		"weirdtype": map[string]int{"meaning": 42},
	}

	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v; want no error", err)
	}

	want := map[string]any{
		"object": map[string]any{"a": "b"},
		"array":  []any{"a", 1},
	}
	if got := r.Vuln().DatabaseSpecific; !reflect.DeepEqual(got, want) {
		t.Errorf("DatabaseSpecific = %v; want %v", got, want)
	}
}

func TestNormalize_AffectedDatabaseSpecificStrip(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().Affected[0].DatabaseSpecific = map[string]any{
		"object":    map[string]any{"a": "b"},
		"array":     []any{"a", 1},
		"scalar":    42,
		"weirdtype": map[string]int{"meaning": 42},
	}

	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v; want no error", err)
	}

	want := map[string]any{
		"object": map[string]any{"a": "b"},
		"array":  []any{"a", 1},
	}
	if got := r.Vuln().Affected[0].DatabaseSpecific; !reflect.DeepEqual(got, want) {
		t.Errorf("DatabaseSpecific = %v; want %v", got, want)
	}
}

func TestNormalize_NoOrigin_DetailsUnchanged(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().Details = "  please do\nnot touch  "

	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v; want no error", err)
	}

	want := "  please do\nnot touch  "
	if got := r.Vuln().Details; got != want {
		t.Errorf("Details = %v; want %v", got, want)
	}
}

func TestNormalize_Origin_DetailsChanged(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().Details = "  please move\nmy details  "
	r.AddOrigin("test-origin", "deadbeef")

	if err := r.Normalize(); err != nil {
		t.Fatalf("Normalize() = %v; want no error", err)
	}

	want := "\n---\n_-= Per source details. Do not edit below this line.=-_\n\n## Source: test-origin (deadbeef)\nplease move\nmy details\n"
	if got := r.Vuln().Details; got != want {
		t.Errorf("Details = %v; want %v", got, want)
	}
}

func TestStripID(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().ID = "TEST-1234-1"

	r.StripID()

	if got := r.ID(); got != "" {
		t.Errorf("ID = %v; want no ID", got)
	}
}

func TestAliasID(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().ID = "TEST-1234-1"

	r.AliasID()

	want := []string{"TEST-1234-1"}
	if got := r.Vuln().Aliases; !slices.Equal(got, want) {
		t.Errorf("Aliases = %v; want %s", got, want)
	}
}

func TestAliasID_ExistingAliases(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().ID = "TEST-1234-1"
	r.Vuln().Aliases = []string{"OTHER-5432-1"}

	r.AliasID()

	want := []string{"OTHER-5432-1", "TEST-1234-1"}
	if got := r.Vuln().Aliases; !slices.Equal(got, want) {
		t.Errorf("Aliases = %v; want %s", got, want)
	}
}

func TestAliasID_Duplicate(t *testing.T) {
	r := testReport(models.EcosystemRubyGems, "example")
	r.Vuln().ID = "TEST-1234-1"
	r.Vuln().Aliases = []string{"TEST-1234-1", "OTHER-5432-1"}

	r.AliasID()

	want := []string{"TEST-1234-1", "OTHER-5432-1"}
	if got := r.Vuln().Aliases; !slices.Equal(got, want) {
		t.Errorf("Aliases = %v; want %s", got, want)
	}
}
