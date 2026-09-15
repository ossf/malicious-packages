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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ossf/malicious-packages/cmd/malosv/internal/reportargs"
	"github.com/ossf/malicious-packages/internal/config"
)

func parseWithResolver(resolver reportargs.ResolverFlags, candidates, bases []string) (map[string][]string, []string, error) {
	a := &reportargs.ReportArguments{
		BasesFn:        func(*config.Config) []string { return bases },
		Resolvers:      resolver,
		IgnoreUnparsed: true,
	}
	unused, err := a.Parse(candidates)
	return a.Reports(), unused, err
}

func TestByReportFile(t *testing.T) {
	tmpDir, bases := setupTestDir(t)
	base1 := bases[0]
	base2 := bases[1]

	mal1Abs := filepath.Join(base1, "npm/package/MAL-1.json")
	mal2Abs := filepath.Join(base2, "pypi/package/MAL-2.json")
	readmeAbs := filepath.Join(base1, "npm/package/README.md")
	dotAbs := filepath.Join(base1, "npm/package/.dotfile")
	subDirAbs := filepath.Join(base1, "npm/package/subdir")
	nonExistentAbs := filepath.Join(base1, "npm/package/MAL-999.json")
	outsideAbs := filepath.Join(tmpDir, "outside.json")
	if err := os.WriteFile(outsideAbs, []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to create outside file: %v", err)
	}

	tests := []struct {
		name       string
		candidates []string
		want       map[string][]string
		wantUnused []string
		wantErr    bool
	}{
		{
			name:       "happy path - single file",
			candidates: []string{mal1Abs},
			want: map[string][]string{
				"npm/package": {mal1Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "happy path - multiple files in different bases",
			candidates: []string{mal1Abs, mal2Abs},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "no separator in candidate",
			candidates: []string{"MAL-1.json"},
			want:       map[string][]string{},
			wantUnused: []string{"MAL-1.json"},
		},
		{
			name:       "non-existent file",
			candidates: []string{nonExistentAbs},
			want:       map[string][]string{},
			wantUnused: []string{nonExistentAbs},
		},
		{
			name:       "not regular file (directory)",
			candidates: []string{subDirAbs},
			want:       map[string][]string{},
			wantUnused: []string{subDirAbs},
		},
		{
			name:       "invalid name (README)",
			candidates: []string{readmeAbs},
			want:       map[string][]string{},
			wantUnused: []string{readmeAbs},
		},
		{
			name:       "invalid name (dotfile)",
			candidates: []string{dotAbs},
			want:       map[string][]string{},
			wantUnused: []string{dotAbs},
		},
		{
			name:       "outside bases",
			candidates: []string{outsideAbs},
			want:       map[string][]string{},
			wantUnused: []string{outsideAbs},
		},
		{
			name:       "mixed candidates",
			candidates: []string{mal1Abs, nonExistentAbs, mal2Abs, "no-sep"},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: []string{nonExistentAbs, "no-sep"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unused, err := parseWithResolver(reportargs.ResolveByFile, tt.candidates, bases)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() reports = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(unused, tt.wantUnused) {
				t.Errorf("Parse() unused = %v, want %v", unused, tt.wantUnused)
			}
		})
	}
}

func TestByDirectoryPath(t *testing.T) {
	tmpDir, bases := setupTestDir(t)
	base1 := bases[0]
	base2 := bases[1]

	dir1Abs := filepath.Join(base1, "npm/package")
	dir2Abs := filepath.Join(base2, "pypi/package")
	nonExistentAbs := filepath.Join(base1, "npm/not-exist")
	outsideAbs := filepath.Join(tmpDir, "outside")
	if err := os.MkdirAll(outsideAbs, 0o755); err != nil {
		t.Fatalf("failed to create outside dir: %v", err)
	}

	mal1Abs := filepath.Join(base1, "npm/package/MAL-1.json")
	mal2Abs := filepath.Join(base2, "pypi/package/MAL-2.json")

	tests := []struct {
		name       string
		candidates []string
		want       map[string][]string
		wantUnused []string
		wantErr    bool
	}{
		{
			name:       "happy path - single directory",
			candidates: []string{dir1Abs},
			want: map[string][]string{
				"npm/package": {mal1Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "happy path - multiple directories",
			candidates: []string{dir1Abs, dir2Abs},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "no separator in candidate",
			candidates: []string{"package"},
			want:       map[string][]string{},
			wantUnused: []string{"package"},
		},
		{
			name:       "non-existent directory",
			candidates: []string{nonExistentAbs},
			want:       map[string][]string{},
			wantUnused: []string{nonExistentAbs},
		},
		{
			name:       "is not a directory (file instead)",
			candidates: []string{mal1Abs},
			want:       map[string][]string{},
			wantUnused: []string{mal1Abs},
		},
		{
			name:       "outside bases",
			candidates: []string{outsideAbs},
			want:       map[string][]string{},
			wantUnused: []string{outsideAbs},
		},
		{
			name:       "mixed candidates",
			candidates: []string{dir1Abs, nonExistentAbs, dir2Abs},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: []string{nonExistentAbs},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unused, err := parseWithResolver(reportargs.ResolveByDirectory, tt.candidates, bases)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() reports = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(unused, tt.wantUnused) {
				t.Errorf("Parse() unused = %v, want %v", unused, tt.wantUnused)
			}
		})
	}
}

func TestByEcosystemAndPackage(t *testing.T) {
	_, bases := setupTestDir(t)
	base1 := bases[0]
	base2 := bases[1]

	mal1Abs := filepath.Join(base1, "npm/package/MAL-1.json")
	mal2Abs := filepath.Join(base2, "pypi/package/MAL-2.json")

	tests := []struct {
		name       string
		candidates []string
		want       map[string][]string
		wantUnused []string
		wantErr    bool
	}{
		{
			name:       "happy path - single ecosystem/package",
			candidates: []string{"npm/package"},
			want: map[string][]string{
				"npm/package": {mal1Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "happy path - multiple ecosystem/package",
			candidates: []string{"npm/package", "pypi/package"},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "no separator in candidate",
			candidates: []string{"package"},
			want:       map[string][]string{},
			wantUnused: []string{"package"},
		},
		{
			name:       "invalid path structure",
			candidates: []string{"/absolute/path"},
			want:       map[string][]string{},
			wantUnused: []string{"/absolute/path"},
		},
		{
			name:       "invalid path structure (normalizes to dot)",
			candidates: []string{"a/../b"},
			want:       map[string][]string{},
			wantUnused: []string{"a/../b"},
		},
		{
			name:       "no reports in path",
			candidates: []string{"npm/empty-package"},
			want:       map[string][]string{},
			wantUnused: []string{"npm/empty-package"},
		},
		{
			name:       "mixed candidates",
			candidates: []string{"npm/package", "npm/empty-package", "pypi/package"},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: []string{"npm/empty-package"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unused, err := parseWithResolver(reportargs.ResolveByEcosystemAndName, tt.candidates, bases)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() reports = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(unused, tt.wantUnused) {
				t.Errorf("Parse() unused = %v, want %v", unused, tt.wantUnused)
			}
		})
	}
}

func TestByID(t *testing.T) {
	_, bases := setupTestDir(t)
	base1 := bases[0]
	base2 := bases[1]

	mal1Abs := filepath.Join(base1, "npm/package/MAL-1.json")
	mal2Abs := filepath.Join(base2, "pypi/package/MAL-2.json")

	tests := []struct {
		name       string
		candidates []string
		want       map[string][]string
		wantUnused []string
		wantErr    bool
	}{
		{
			name:       "happy path - single ID",
			candidates: []string{"MAL-1"},
			want: map[string][]string{
				"npm/package": {mal1Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "happy path - multiple IDs in different bases",
			candidates: []string{"MAL-1", "MAL-2"},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: nil,
		},
		{
			name:       "candidate with separator is skipped",
			candidates: []string{"npm/MAL-1"},
			want:       map[string][]string{},
			wantUnused: []string{"npm/MAL-1"},
		},
		{
			name:       "ID not found",
			candidates: []string{"MAL-999"},
			want:       map[string][]string{},
			wantUnused: []string{"MAL-999"},
		},
		{
			name:       "mixed candidates",
			candidates: []string{"MAL-1", "MAL-999", "MAL-2", "npm/MAL-1"},
			want: map[string][]string{
				"npm/package":  {mal1Abs},
				"pypi/package": {mal2Abs},
			},
			wantUnused: []string{"npm/MAL-1", "MAL-999"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unused, err := parseWithResolver(reportargs.ResolveByID, tt.candidates, bases)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Sort slices in got maps because filepath.WalkDir order is not guaranteed.
			for k := range got {
				slices.Sort(got[k])
			}
			for k := range tt.want {
				slices.Sort(tt.want[k])
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() reports = %v, want %v", got, tt.want)
			}

			// Sort unused as well, just in case.
			slices.Sort(unused)
			slices.Sort(tt.wantUnused)
			if !reflect.DeepEqual(unused, tt.wantUnused) {
				t.Errorf("Parse() unused = %v, want %v", unused, tt.wantUnused)
			}
		})
	}
}
