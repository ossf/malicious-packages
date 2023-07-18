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
