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

package reportio_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ossf/malicious-packages/internal/reportio"
)

func TestValidatePath(t *testing.T) {
	tests := []string{
		"a/b",
		"a/b/c",
		"a/b/c/d",
		"a/b/c/d/e",
		"npm/@namespace/package",
		"pypi/example",
		"golang/github.com/ossf/malicious-packages",
		"a/../b/c",
		"a/./b/../c/",
		"a/b/",
		"a//////b",
	}
	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			err := reportio.ValidatePath(test)
			if err != nil {
				t.Errorf("ValidatePath() = %v; want no error", err)
			}
		})
	}
}

func TestValidatePath_Invalid(t *testing.T) {
	tests := []string{
		"a",
		"..",
		"a/../b",
		"./c",
		"/etc/passwd",
		"",
		".",
		"a/..",
		"a/b/./c/./d/e/../../../..",
	}
	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			err := reportio.ValidatePath(test)
			if err == nil {
				t.Error("ValidatePath() = nil; want an error")
			}
		})
	}
}

func TestIsPossibleReport(t *testing.T) {
	tests := []struct {
		name string
		mode fs.FileMode
		want bool
	}{
		{
			name: "MAL-1234-1.json",
			mode: 0,
			want: true,
		},
		{
			name: "foobar.ext",
			mode: 0,
			want: true,
		},
		{
			name: "README.md",
			mode: 0,
			want: false,
		},
		{
			name: "subdir",
			mode: fs.ModeDir,
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := reportio.IsPossibleReport(test.name, test.mode)
			if got != test.want {
				t.Fatalf("IsPossibleReport() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPreparePath(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base")
	path := "my/path"

	want := filepath.Join(base, path)

	got, err := reportio.PreparePath(path, base)
	if err != nil {
		t.Fatalf("PreparePath() = %v; want no error", err)
	}
	if got != want {
		t.Errorf("PreparePath() = %q; want %q", got, want)
	}

	if s, err := os.Stat(got); err != nil {
		t.Fatalf("Stat(%q) = %v; want no error", got, err)
	} else if !s.IsDir() {
		t.Errorf("%q is not a directory", got)
	}
}

func TestPreparePath_Errors(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
		base string
	}{
		{
			name: "not under base",
			path: "path/../../out",
			base: filepath.Join(dir, "base"),
		},
		{
			name: "full path traversal",
			path: "../../../../../../../../path/out",
			base: filepath.Join(dir, "base"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := reportio.PreparePath(test.path, test.base)
			if err == nil {
				t.Errorf("PreparePath = nil; want an error")
			}
		})
	}
}

func TestMoveReport(t *testing.T) {
	dir := t.TempDir()
	baseSrc := filepath.Join(dir, "src")
	baseDest := filepath.Join(dir, "dest")
	path := "eco/name"
	reportPath := filepath.Join(path, "report.json")

	if err := os.MkdirAll(filepath.Join(baseSrc, path), 0o777); err != nil {
		t.Fatalf("MkdirAll() = %v; want no error", err)
	}
	if err := os.WriteFile(filepath.Join(baseSrc, reportPath), []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile() = %v; want no error", err)
	}

	if err := reportio.MoveReport(filepath.Join(baseSrc, reportPath), baseSrc, baseDest); err != nil {
		t.Fatalf("MoveReport() = %v; want no error", err)
	}

	if got, err := os.ReadFile(filepath.Join(baseDest, reportPath)); err != nil {
		t.Fatalf("ReadFile() = %v; want no error", err)
	} else if want := "test"; string(got) != want {
		t.Errorf("Report contents = %q; want %q", string(got), want)
	}

	if _, err := os.Stat(filepath.Join(baseSrc, reportPath)); !os.IsNotExist(err) {
		t.Errorf("Stat() = %v; want not exists error", err)
	}
}

func TestMoveReport_Errors(t *testing.T) {
	dir := t.TempDir()
	baseSrc := filepath.Join(dir, "src")
	baseDest := filepath.Join(dir, "dest")
	path := "eco/name"
	reportPath := filepath.Join(path, "report.json")

	if err := os.MkdirAll(filepath.Join(baseSrc, path, "sub"), 0o777); err != nil {
		t.Fatalf("MkdirAll() = %v; want no error", err)
	}
	if err := os.MkdirAll(filepath.Join(baseDest, path), 0o777); err != nil {
		t.Fatalf("MkdirAll() = %v; want no error", err)
	}
	// Create test files
	for _, name := range []string{
		filepath.Join(baseSrc, reportPath),
		filepath.Join(baseDest, reportPath),
		filepath.Join(dir, "outside.json"),
	} {
		if err := os.WriteFile(name, []byte{}, 0o600); err != nil {
			t.Fatalf("WriteFile(%q) = %v; want no error", name, err)
		}
	}

	tests := []struct {
		name string
		path string
	}{
		{
			name: "missing source report",
			path: filepath.Join(baseSrc, "eco/name/not_exist.json"),
		},
		{
			name: "source report is dir",
			path: filepath.Join(baseSrc, "eco/name/sub"),
		},
		{
			name: "dest already occupied",
			path: filepath.Join(baseSrc, reportPath),
		},
		{
			name: "report outside base",
			path: filepath.Join(dir, "outside.json"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := reportio.MoveReport(test.path, baseSrc, baseDest)
			if err == nil {
				t.Fatalf("MoveReport() = nil; want an error")
			}
		})
	}
}
