// Copyright 2026 Malicious Packages Authors
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

package reportargs_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ossf/malicious-packages/cmd/malosv/internal/reportargs"
	"github.com/ossf/malicious-packages/internal/config"
)

func TestReportArguments_HasName(t *testing.T) {
	a := &reportargs.ReportArguments{}
	if got := a.HasName("anything"); got {
		t.Errorf("HasName(%q) = %t; want false", "anything", got)
	}
}

func TestReportArguments_Usage(t *testing.T) {
	tests := []struct {
		name      string
		resolvers reportargs.ResolverFlags
		want      string
	}{
		{
			name:      "only file resolver",
			resolvers: reportargs.ResolveByFile,
			want:      "<filename> [<filename> ...]",
		},
		{
			name:      "file and directory resolvers",
			resolvers: reportargs.ResolveByFile | reportargs.ResolveByDirectory,
			want:      "<filename|dirname> [<filename|dirname> ...]",
		},
		{
			name:      "all resolvers",
			resolvers: reportargs.AllResolvers,
			want:      "<filename|dirname|ecosystem/package|report_id> [<filename|dirname|ecosystem/package|report_id> ...]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &reportargs.ReportArguments{Resolvers: tt.resolvers}
			if got := a.Usage(); got != tt.want {
				t.Errorf("Usage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReportArguments_GetAndReports(t *testing.T) {
	var a *reportargs.ReportArguments
	if got := a.Reports(); got != nil {
		t.Errorf("Reports() on nil receiver = %v; want nil", got)
	}
	gotNil := a.Get()
	if gotNil == nil {
		t.Error("Get() on nil receiver = nil; want typed nil map")
	}
	m, ok := gotNil.(map[string][]string)
	if !ok {
		t.Errorf("Get() on nil receiver returned type %T; want map[string][]string", gotNil)
	}
	if m != nil {
		t.Errorf("Get() on nil receiver wrapped map = %v; want nil map", m)
	}

	a = &reportargs.ReportArguments{}
	reportsMap := map[string][]string{
		"npm/package": {"/path/to/report.json"},
	}
	a.SetReportsForTesting(reportsMap)

	if got := a.Reports(); !reflect.DeepEqual(got, reportsMap) {
		t.Errorf("Reports() = %v, want %v", got, reportsMap)
	}
	if got := a.Get(); !reflect.DeepEqual(got, reportsMap) {
		t.Errorf("Get() = %v, want %v", got, reportsMap)
	}
}

func TestReportArguments_Parse(t *testing.T) {
	_, bases := setupTestDir(t)
	base1 := bases[0]
	fileAbs := filepath.Join(base1, "npm/package/MAL-1.json")

	cfg := &config.Config{}
	basesFn := func(_ *config.Config) []string {
		return []string{base1}
	}

	tests := []struct {
		name           string
		resolvers      reportargs.ResolverFlags
		ignoreUnparsed bool
		args           []string
		wantReports    map[string][]string
		wantUnused     []string
		wantErr        bool
	}{
		{
			name:           "happy path - resolve by file",
			resolvers:      reportargs.ResolveByFile,
			ignoreUnparsed: false,
			args:           []string{fileAbs},
			wantReports: map[string][]string{
				"npm/package": {fileAbs},
			},
			wantUnused: nil,
			wantErr:    false,
		},
		{
			name:           "unparsed arguments with error",
			resolvers:      reportargs.ResolveByFile,
			ignoreUnparsed: false,
			args:           []string{fileAbs, "unparsed-arg"},
			wantReports:    nil,
			wantUnused:     nil,
			wantErr:        true,
		},
		{
			name:           "unparsed arguments ignored",
			resolvers:      reportargs.ResolveByFile,
			ignoreUnparsed: true,
			args:           []string{fileAbs, "unparsed-arg"},
			wantReports: map[string][]string{
				"npm/package": {fileAbs},
			},
			wantUnused: []string{"unparsed-arg"},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &reportargs.ReportArguments{
				Config:         cfg,
				BasesFn:        basesFn,
				Resolvers:      tt.resolvers,
				IgnoreUnparsed: tt.ignoreUnparsed,
			}
			unused, err := a.Parse(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(unused, tt.wantUnused) {
				t.Errorf("Parse() unused = %v, want %v", unused, tt.wantUnused)
			}
			if !reflect.DeepEqual(a.Reports(), tt.wantReports) {
				t.Errorf("Parse() reports = %v, want %v", a.Reports(), tt.wantReports)
			}
		})
	}
}

func TestReportArguments_Parse_DuplicateReport(t *testing.T) {
	_, bases := setupTestDir(t)
	base1 := bases[0]
	fileAbs := filepath.Join(base1, "npm/package/MAL-1.json")

	cfg := &config.Config{}
	basesFn := func(_ *config.Config) []string {
		return []string{base1}
	}

	a := &reportargs.ReportArguments{
		Config:    cfg,
		BasesFn:   basesFn,
		Resolvers: reportargs.ResolveByFile | reportargs.ResolveByEcosystemAndName,
	}

	// We pass the file as both a filename candidate and an ecosystem/package candidate.
	_, err := a.Parse([]string{fileAbs, "npm/package"})
	if err == nil {
		t.Error("Parse() expected duplicate report error, got nil")
	}
}

func TestReportArguments_Parse_ResolverError(t *testing.T) {
	cfg := &config.Config{}
	basesFn := func(_ *config.Config) []string {
		return []string{"/non-existent-directory-to-cause-error"}
	}
	a := &reportargs.ReportArguments{
		Config:    cfg,
		BasesFn:   basesFn,
		Resolvers: reportargs.ResolveByID,
	}
	_, err := a.Parse([]string{"MAL-1"})
	if err == nil {
		t.Error("Parse() expected error when walking non-existent directory, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Parse() expected os.ErrNotExist, got %v", err)
	}
}
