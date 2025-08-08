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
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestMerge_MismatchName(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example1")
	other := testReport(osvschema.EcosystemNPM, "example2")
	if err := r.Merge(other); err == nil || !errors.Is(err, report.ErrMergeFailure) {
		t.Fatalf("Merge() = %v; want %v", err, report.ErrMergeFailure)
	}
}

func TestMerge_NuGetName(t *testing.T) {
	r := testReport(osvschema.EcosystemNuGet, "example.Utility.Test")
	other := testReport(osvschema.EcosystemNuGet, "Example.utility.TEST")
	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}
}

func TestMerge_MismatchEcosystem(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example1")
	other := testReport(osvschema.EcosystemPyPI, "example2")
	if err := r.Merge(other); err == nil || !errors.Is(err, report.ErrMergeFailure) {
		t.Fatalf("Merge() = %v; want %v", err, report.ErrMergeFailure)
	}
}

func TestMerge_WithID(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().ID = "MAL-1234-abcd"

	if err := r.Merge(other); err == nil || !errors.Is(err, report.ErrMergeFailure) {
		t.Fatalf("Merge() = %v; want %v", err, report.ErrMergeFailure)
	}
}

func TestMerge_CommonOrigin(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.AddOrigin("test-origin", "deadbeef")
	other := testReport(osvschema.EcosystemNPM, "example")
	other.AddOrigin("test-origin", "deadbeef")

	if err := r.Merge(other); err == nil || !errors.Is(err, report.ErrMergeFailure) {
		t.Fatalf("Merge() = %v; want %v", err, report.ErrMergeFailure)
	}
}

func TestMerge_NormalizationFail(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	other := testReport(osvschema.EcosystemNPM, "example")
	// Other is not expected to have multiple origins (i.e. never merged before)
	other.AddOrigin("test-origin", "deadbeef")
	other.AddOrigin("another-origin", "00000000")

	if err := r.Merge(other); err == nil || !errors.Is(err, report.ErrNormalizing) {
		t.Fatalf("Merge() = %v; want %v", err, report.ErrNormalizing)
	}
}

func TestMerge_Ranges(t *testing.T) {
	r1 := osvschema.Range{
		Type: osvschema.RangeEcosystem,
		Events: []osvschema.Event{
			{
				Introduced: "a",
			},
			{
				Fixed: "b",
			},
		},
	}
	r2 := osvschema.Range{
		Type: osvschema.RangeEcosystem,
		Events: []osvschema.Event{
			{
				Introduced: "a",
			},
			{
				Fixed: "c",
			},
		},
	}
	r3 := osvschema.Range{
		Type: osvschema.RangeSemVer,
		Events: []osvschema.Event{
			{
				Introduced: "a",
			},
		},
	}
	r4 := osvschema.Range{
		Type: osvschema.RangeSemVer,
		Events: []osvschema.Event{
			{
				Introduced: "a",
			},
		},
	}
	r5 := osvschema.Range{
		Type: osvschema.RangeEcosystem,
		Events: []osvschema.Event{
			{
				Introduced: "a",
			},
			{
				Fixed: "c",
			},
		},
	}
	r6 := osvschema.Range{
		Type: osvschema.RangeEcosystem,
		Events: []osvschema.Event{
			{
				Introduced: "a",
			},
		},
	}

	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Affected[0].Ranges = []osvschema.Range{
		r1,
		r2,
		r3,
	}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Affected[0].Ranges = []osvschema.Range{
		r4,
		r5,
		r6,
	}
	want := []osvschema.Range{
		r1, r2, r3, r6,
	}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Affected[0].Ranges; !reflect.DeepEqual(got, want) {
		t.Fatalf("Ranges = %v; want %v", got, want)
	}
}

func TestMerge_Versions(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Affected[0].Versions = []string{"z", "b", "c"}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Affected[0].Versions = []string{"b", "c", "d"}

	want := []string{"z", "b", "c", "d"}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Affected[0].Versions; !slices.Equal(got, want) {
		t.Fatalf("Versions = %v; want %v", got, want)
	}
}

func TestMerge_NoSeverities(t *testing.T) {
	sev := osvschema.Severity{
		Type:  osvschema.SeverityCVSSV3,
		Score: "9.8",
	}

	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Severity = []osvschema.Severity{sev}
	r.Vuln().Affected[0].Severity = []osvschema.Severity{sev}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Severity = []osvschema.Severity{sev}
	other.Vuln().Affected[0].Severity = []osvschema.Severity{sev}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Severity; got != nil {
		t.Fatalf("Severity = %v; want nil", got)
	}
	if got := r.Vuln().Affected[0].Severity; got != nil {
		t.Fatalf("Affected Severity = %v; want nil", got)
	}
}

func TestMerge_NoEcosystemSpecificData(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Affected[0].EcosystemSpecific = map[string]any{
		"test1": "test",
	}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Affected[0].EcosystemSpecific = map[string]any{
		"test2": "test",
	}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Affected[0].EcosystemSpecific; got != nil {
		t.Fatalf("Affected EcosystemSpecific = %v; want nil", got)
	}
}

func TestMerge_Aliases(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().ID = "id"
	r.Vuln().Aliases = []string{"z", "b", "c"}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Aliases = []string{"b", "c", "d", "id"}

	want := []string{"z", "b", "c", "d"}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Aliases; !slices.Equal(got, want) {
		t.Fatalf("Aliases = %v; want %v", got, want)
	}
}

func TestMerge_Related(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Related = []string{"z", "b", "c"}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Related = []string{"b", "c", "d"}

	want := []string{"z", "b", "c", "d"}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Related; !slices.Equal(got, want) {
		t.Fatalf("Related = %v; want %v", got, want)
	}
}

func TestMerge_References(t *testing.T) {
	ref1 := osvschema.Reference{
		Type: osvschema.ReferenceAdvisory,
		URL:  "https://example.com/advisory",
	}
	ref2 := osvschema.Reference{
		Type: osvschema.ReferenceFix,
		URL:  "https://example.com/fix",
	}
	ref3 := osvschema.Reference{
		Type: osvschema.ReferenceReport,
		URL:  "https://example.com/report",
	}
	ref4 := osvschema.Reference{
		Type: osvschema.ReferenceArticle,
		URL:  "https://example.com/advisory",
	}
	ref5 := osvschema.Reference{
		Type: osvschema.ReferenceReport,
		URL:  "https://example.com/id.json",
	}
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().ID = "id"
	r.Vuln().References = []osvschema.Reference{ref1, ref2, ref3}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().References = []osvschema.Reference{ref2, ref3, ref4, ref5}

	want := []osvschema.Reference{ref1, ref2, ref3, ref4}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().References; !slices.Equal(got, want) {
		t.Fatalf("References = %v; want %v", got, want)
	}
}

func TestMerge_Credits(t *testing.T) {
	c1 := osvschema.Credit{
		Name:    "John Appleseed",
		Type:    osvschema.CreditFinder,
		Contact: []string{"john.appleseed@example.com"},
	}
	c2 := osvschema.Credit{
		Name:    "Jane Doe",
		Type:    osvschema.CreditReporter,
		Contact: []string{"janedoe123@example.com"},
	}
	c3 := osvschema.Credit{
		Name:    "Anonymous Coward",
		Type:    osvschema.CreditOther,
		Contact: []string{"no-reply@example.com"},
	}
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Credits = []osvschema.Credit{c1, c2}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Credits = []osvschema.Credit{c2, c3}

	want := []osvschema.Credit{c3, c2, c1}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Credits; !reflect.DeepEqual(got, want) {
		t.Fatalf("Credits = %v; want %v", got, want)
	}
}

func TestMerge_CreditsContactMerge(t *testing.T) {
	c1 := osvschema.Credit{
		Name:    "John Appleseed",
		Type:    osvschema.CreditFinder,
		Contact: []string{"john.appleseed@example.com"},
	}
	c2 := osvschema.Credit{
		Name:    "XYZ",
		Type:    osvschema.CreditFinder,
		Contact: []string{"xyz@example.com"},
	}
	c3 := osvschema.Credit{
		Name:    "John Appleseed",
		Type:    osvschema.CreditFinder,
		Contact: []string{"https://twitter.com/john_appleseed_this_does_not_exist"},
	}
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Credits = []osvschema.Credit{c1}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Credits = []osvschema.Credit{c2, c3}

	want := []osvschema.Credit{
		{
			Name:    "John Appleseed",
			Type:    osvschema.CreditFinder,
			Contact: []string{"john.appleseed@example.com", "https://twitter.com/john_appleseed_this_does_not_exist"},
		},
		{
			Name:    "XYZ",
			Type:    osvschema.CreditFinder,
			Contact: []string{"xyz@example.com"},
		},
	}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Credits; !reflect.DeepEqual(got, want) {
		t.Fatalf("Credits = %v; want %v", got, want)
	}
}

func TestMerge_DetailsParseError(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Details = "\n---\n_-= Per source details. Do not edit below this line.=-_\n\n---\n_-= Per source details. Do not edit below this line.=-_\n"
	other := testReport(osvschema.EcosystemNPM, "example")

	if err := r.Merge(other); err == nil || !errors.Is(err, report.ErrMergeFailure) {
		t.Fatalf("Merge() = %v; want %v", err, report.ErrMergeFailure)
	}
}

func TestMerge_ReportsBothHaveUserContributions(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Details = "this is my user contributed report"
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Details = "no, this is my user contributed report"

	if err := r.Merge(other); err == nil || !errors.Is(err, report.ErrMergeFailure) {
		t.Fatalf("Merge() = %v; want %v", err, report.ErrMergeFailure)
	}
}

func TestMerge_ReportUserContributions(t *testing.T) {
	want := "this is my user contributed report"
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Details = want
	other := testReport(osvschema.EcosystemNPM, "example")

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}

	if l := len(gotSources); l > 0 {
		t.Errorf("ParseDetails() len(sources) = %d, want no sources", l)
	}

	if gotUser != want {
		t.Errorf("ParseDetails() user = %v, want %v", gotUser, want)
	}
}

func TestMerge_OtherUserContributions(t *testing.T) {
	want := "no, this is my user contributed report"
	r := testReport(osvschema.EcosystemNPM, "example")
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Details = want

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}

	if l := len(gotSources); l > 0 {
		t.Errorf("ParseDetails() len(sources) = %d, want no sources", l)
	}

	if gotUser != want {
		t.Errorf("ParseDetails() user = %v, want %v", gotUser, want)
	}
}

func TestMerge_Details(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	o1 := r.AddOrigin("test-origin", "deadbeef")
	o2 := r.AddOrigin("another-test-origin", "fffe")
	r.SetDetails("this is a \nuser contribution", map[*report.OriginRef]string{
		o1: "test report 1",
		o2: "test report 2",
	})
	other := testReport(osvschema.EcosystemNPM, "example")
	o3 := other.AddOrigin("test-origin", "00000000")
	other.Vuln().Details = "a longer test report 1"

	wantUser := "this is a \nuser contribution"
	wantSources := map[*report.OriginRef]string{
		o2: "test report 2",
		o3: "a longer test report 1",
	}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v, want %v", gotUser, wantUser)
	}

	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Errorf("ParseDetails() sources = %v, want %v", gotSources, wantSources)
	}
}

func TestMerge_Origins(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	o1 := r.AddOrigin("test-origin", "deadbeef")
	o2 := r.AddOrigin("another-test-origin", "fffe")
	other := testReport(osvschema.EcosystemNPM, "example")
	o3 := other.AddOrigin("test-origin", "00000000")

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	want := []*report.OriginRef{o1, o2, o3}
	if got := r.Origins(); !slices.Equal(got, want) {
		t.Errorf("Origins() = %v; want %v", got, want)
	}
}

func TestMerge_DatabaseSpecific(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().DatabaseSpecific = map[string]any{
		"object": map[string]any{
			"unique1": "foo",
			"common":  "bar",
			"integer": 42,
		},
		"array":  []any{"a", "b", "c"},
		"scalar": "test1",
	}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().DatabaseSpecific = map[string]any{
		"object": map[string]any{
			"unique2": "foo",
			"common":  "baz",
			"float":   3.14159,
		},
		"array":  []any{"b", "c", "d"},
		"scalar": "test1",
	}

	want := map[string]any{
		"object": map[string]any{
			"unique1": "foo",
			"unique2": "foo",
			"common":  "bar",
			"integer": 42,
			"float":   3.14159,
		},
		"array": []any{"a", "b", "c", "b", "c", "d"},
	}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().DatabaseSpecific; !reflect.DeepEqual(got, want) {
		t.Errorf("DatabaseSpecific = %v; want %v", got, want)
	}
}

func TestMerge_AffectedDatabaseSpecific(t *testing.T) {
	r := testReport(osvschema.EcosystemNPM, "example")
	r.Vuln().Affected[0].DatabaseSpecific = map[string]any{
		"object": map[string]any{
			"unique1": "foo",
			"common":  "bar",
		},
		"array":  []any{"a", "b"},
		"scalar": "test1",
	}
	other := testReport(osvschema.EcosystemNPM, "example")
	other.Vuln().Affected[0].DatabaseSpecific = map[string]any{
		"object": map[string]any{
			"unique2": "foo",
			"common":  "baz",
		},
		"array":  []any{"b", "c"},
		"scalar": "test1",
	}

	want := map[string]any{
		"object": map[string]any{
			"unique1": "foo",
			"unique2": "foo",
			"common":  "bar",
		},
		"array": []any{"a", "b", "b", "c"},
	}

	if err := r.Merge(other); err != nil {
		t.Fatalf("Merge() = %v; want no error", err)
	}

	if got := r.Vuln().Affected[0].DatabaseSpecific; !reflect.DeepEqual(got, want) {
		t.Errorf("DatabaseSpecific = %v; want %v", got, want)
	}
}

func TestMerge_PublishTimes(t *testing.T) {
	time1 := time.Date(2023, 0o6, 19, 8, 46, 0, 0, time.UTC)
	time2 := time.Date(2023, 12, 25, 10, 0o0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		report       time.Time
		other        time.Time
		want         time.Time
		wantModified bool
	}{
		{
			name:         "no times",
			wantModified: true,
		},
		{
			name:   "report only",
			report: time1,
			want:   time1,
		},
		{
			name:  "other only",
			other: time1,
			want:  time1,
		},
		{
			name:   "report bigger",
			report: time1,
			other:  time2,
			want:   time1,
		},
		{
			name:   "other bigger",
			report: time2,
			other:  time1,
			want:   time1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := testReport(osvschema.EcosystemNPM, "example")
			r.Vuln().Published = test.report
			other := testReport(osvschema.EcosystemNPM, "example")
			other.Vuln().Published = test.other

			if err := r.Merge(other); err != nil {
				t.Fatalf("Merge() = %v; want no error", err)
			}

			got := r.Vuln().Published
			want := test.want
			if test.wantModified {
				want = r.Vuln().Modified
			}
			if got != want {
				t.Errorf("Publihsed = %v; want %v", got, want)
			}
		})
	}
}
