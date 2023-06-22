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

//nolint:goconst
package report_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ossf/malicious-packages/internal/report"
)

func reportWithDetail(details string) *report.Report {
	rJSON := `{ "schema_version": "1.5.0", "summary": "test report", "affected": [{"package":{"ecosystem": "npm", "name": "example"},"versions":["1"]}], "details": "%s" }`
	r, err := report.ReadJSON(bytes.NewBufferString(fmt.Sprintf(rJSON, strings.ReplaceAll(details, "\"", "\\\""))))
	if err != nil {
		panic(err)
	}
	return r
}

func TestParseDetails_EmptyNoOrigins(t *testing.T) {
	r := reportWithDetail("")
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != "" {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, "")
	}
	if len(gotSources) != 0 {
		t.Errorf("ParseDetails() sources = %v; want empty slice", gotSources)
	}
}

func TestParseDetails_EmptyOneHeader(t *testing.T) {
	r := reportWithDetail(`\n##= Per source details. Do not edit below this line. =##\n`)
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != "" {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, "")
	}
	if len(gotSources) != 0 {
		t.Errorf("ParseDetails() sources = %v; want empty slice", gotSources)
	}
}

func TestParseDetails_TwoHeaders(t *testing.T) {
	r := reportWithDetail(`hello\n##= Per source details. Do not edit below this line. =##\nworld\n##= Per source details. Do not edit below this line. =##\n!`)
	_, _, err := r.ParseDetails()
	if err == nil || !errors.Is(err, report.ErrInvalidDetails) {
		t.Fatalf("ParseDetails() = %v; want %v", err, report.ErrInvalidDetails)
	}
}

func TestParseDetails_NoHeader(t *testing.T) {
	r := reportWithDetail(`\n\n\n   here is an\namazing\nreport   \n\n\n`)
	wantUser := "here is an\namazing\nreport"
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, wantUser)
	}
	if len(gotSources) != 0 {
		t.Errorf("ParseDetails() sources = %v; want empty slice", gotSources)
	}
}

func TestParseDetails_WithHeader(t *testing.T) {
	r := reportWithDetail(`here is an\namazing\nreport\n\n##= Per source details. Do not edit below this line. =##\n`)
	wantUser := "here is an\namazing\nreport"
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, wantUser)
	}
	if len(gotSources) != 0 {
		t.Errorf("ParseDetails() sources = %v; want empty slice", gotSources)
	}
}

func TestParseDetails_InvalidSourceSection(t *testing.T) {
	r := reportWithDetail(`user contributed report\n  ...\n\n##= Per source details. Do not edit below this line. =##\n\ninvalid`)
	_, _, err := r.ParseDetails()
	if err == nil || !errors.Is(err, report.ErrInvalidDetails) {
		t.Fatalf("ParseDetails() = %v; want %v", err, report.ErrInvalidDetails)
	}
}

func TestParseDetails_Sources_NoOrigin(t *testing.T) {
	r := reportWithDetail(`user contributed report\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\n`)
	_, _, err := r.ParseDetails()
	if err == nil || !errors.Is(err, report.ErrInvalidDetails) {
		t.Fatalf("ParseDetails() = %v; want %v", err, report.ErrInvalidDetails)
	}
}

func TestParseDetails_Sources_WrongOrigin(t *testing.T) {
	r := reportWithDetail(`user contributed report\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\n`)
	r.AddOrigin("test-source", "01234567")
	_, _, err := r.ParseDetails()
	if err == nil || !errors.Is(err, report.ErrInvalidDetails) {
		t.Fatalf("ParseDetails() = %v; want %v", err, report.ErrInvalidDetails)
	}
}

func TestParseDetails_Sources_OneEmpty(t *testing.T) {
	r := reportWithDetail(`user contributed report\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\n`)
	o := r.AddOrigin("test-source", "deadbeef")
	wantUser := "user contributed report"
	wantSources := map[*report.OriginRef]string{
		o: "",
	}
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, wantUser)
	}
	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Errorf("ParseDetails() sources = %v; want %v", gotSources, wantSources)
	}
}

func TestParseDetails_Sources_Single(t *testing.T) {
	r := reportWithDetail(`user contributed report\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\n\nthis\nis a\ntest.   \n`)
	o := r.AddOrigin("test-source", "deadbeef")
	wantUser := "user contributed report"
	wantSources := map[*report.OriginRef]string{
		o: "this\nis a\ntest.",
	}
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, wantUser)
	}
	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Errorf("ParseDetails() sources = %v; want %v", gotSources, wantSources)
	}
}

func TestParseDetails_Sources_Two(t *testing.T) {
	r := reportWithDetail(`user contributed report\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\nsource one\n\n###= Source: another-test-source (abcdef123) =###\n\nsource two  \n\n`)
	o1 := r.AddOrigin("test-source", "deadbeef")
	o2 := r.AddOrigin("another-test-source", "abcdef123")
	wantUser := "user contributed report"
	wantSources := map[*report.OriginRef]string{
		o1: "source one",
		o2: "source two",
	}
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, wantUser)
	}
	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Errorf("ParseDetails() sources = %v; want %v", gotSources, wantSources)
	}
}

func TestParseDetails_Sources_TwoOneEmpty(t *testing.T) {
	r := reportWithDetail(`user contributed report\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\n\n###= Source: another-test-source (abcdef123) =###\n\nsource two  \n\n`)
	o1 := r.AddOrigin("test-source", "deadbeef")
	o2 := r.AddOrigin("another-test-source", "abcdef123")
	wantUser := "user contributed report"
	wantSources := map[*report.OriginRef]string{
		o1: "",
		o2: "source two",
	}
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, wantUser)
	}
	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Errorf("ParseDetails() sources = %v; want %v", gotSources, wantSources)
	}
}

func TestSetDetails_Empty(t *testing.T) {
	r := reportWithDetail("")
	r.SetDetails("")
	want := "\n##= Per source details. Do not edit below this line. =##\n"
	if got := r.RawDetails(); got != want {
		t.Errorf("RawDetails() = %v; want %v", got, want)
	}
}

func TestSetDetails_UserContributionOnly(t *testing.T) {
	r := reportWithDetail("")
	r.SetDetails("    this\nis a\nreport.   \n\n")
	want := "this\nis a\nreport.\n\n##= Per source details. Do not edit below this line. =##\n"
	if got := r.RawDetails(); got != want {
		t.Errorf("RawDetails() = %v; want %v", got, want)
	}
}

func TestSetDetails_SingleSource(t *testing.T) {
	r := reportWithDetail("")
	o := r.AddOrigin("test-source", "deadbeef")
	r.SetDetails("user contribution", map[*report.OriginRef]string{
		o: "source one",
	})
	want := "user contribution\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\nsource one\n"
	if got := r.RawDetails(); got != want {
		t.Errorf("RawDetails() = %v; want %v", got, want)
	}
}

func TestSetDetails_TwoSources(t *testing.T) {
	r := reportWithDetail("")
	o1 := r.AddOrigin("test-source", "deadbeef")
	o2 := r.AddOrigin("another-test-source", "abcdef123")
	r.SetDetails("user contribution", map[*report.OriginRef]string{
		o1: "source one",
	}, map[*report.OriginRef]string{
		o2: "source two",
	})
	want := "user contribution\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: another-test-source (abcdef123) =###\nsource two\n\n###= Source: test-source (deadbeef) =###\nsource one\n"
	if got := r.RawDetails(); got != want {
		t.Errorf("RawDetails() = %v; want %v", got, want)
	}
}

func TestSetDetails_TwoSourcesOneEmpty(t *testing.T) {
	r := reportWithDetail("")
	o1 := r.AddOrigin("test-source", "deadbeef")
	o2 := r.AddOrigin("another-test-source", "abcdef123")
	r.SetDetails("user contribution", map[*report.OriginRef]string{
		o1: "",
	}, map[*report.OriginRef]string{
		o2: "source two",
	})
	want := "user contribution\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: another-test-source (abcdef123) =###\nsource two\n"
	if got := r.RawDetails(); got != want {
		t.Errorf("RawDetails() = %v; want %v", got, want)
	}
}

func TestSetDetails_SameSourceChooseLongest(t *testing.T) {
	r := reportWithDetail("")
	o1 := r.AddOrigin("test-source", "deadbeef")
	o2 := r.AddOrigin("test-source", "abcdef123")
	o3 := r.AddOrigin("test-source", "00000000")
	r.SetDetails("user contribution", map[*report.OriginRef]string{
		o3: "short report",
	}, map[*report.OriginRef]string{
		o1: "this report is longer",
		o2: "this is a report",
	})
	want := "user contribution\n\n##= Per source details. Do not edit below this line. =##\n\n###= Source: test-source (deadbeef) =###\nthis report is longer\n"
	if got := r.RawDetails(); got != want {
		t.Errorf("RawDetails() = %v; want %v", got, want)
	}
}

func TestSetAndParse(t *testing.T) {
	r := reportWithDetail("")
	o1 := r.AddOrigin("test-source", "deadbeef")
	o2 := r.AddOrigin("another-test-source", "abcdef123")
	wantUser := "this\nis a\nreport."
	wantSources := map[*report.OriginRef]string{
		o1: "source\none\ndetails",
		o2: "source two\n\ndetails as well.",
	}
	r.SetDetails(wantUser, wantSources)
	gotUser, gotSources, err := r.ParseDetails()
	if err != nil {
		t.Fatalf("ParseDetails() = %v; want no error", err)
	}
	if gotUser != wantUser {
		t.Errorf("ParseDetails() user = %v; want = %v", gotUser, wantUser)
	}
	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Errorf("ParseDetails() sources = %v; want %v", gotSources, wantSources)
	}
}
