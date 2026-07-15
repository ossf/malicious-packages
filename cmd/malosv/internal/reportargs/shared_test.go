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
	"testing"
)

func setupTestDir(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()

	base1 := filepath.Join(dir, "base1")
	base2 := filepath.Join(dir, "base2")

	for _, b := range []string{base1, base2} {
		if err := os.MkdirAll(b, 0o755); err != nil {
			t.Fatalf("failed to create base dir %s: %v", b, err)
		}
	}

	// Create test files
	files := []string{
		"base1/npm/package/MAL-1.json",
		"base1/npm/package/README.md",
		"base1/npm/package/.dotfile",
		"base2/pypi/package/MAL-2.json",
	}

	for _, f := range files {
		fullPath := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("failed to create dir for %s: %v", f, err)
		}
		if err := os.WriteFile(fullPath, []byte("{}"), 0o600); err != nil {
			t.Fatalf("failed to write file %s: %v", f, err)
		}
	}

	// Create a subdirectory inside base1/npm/package (non-regular file test)
	subDir := filepath.Join(base1, "npm/package/subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	return dir, []string{base1, base2}
}
