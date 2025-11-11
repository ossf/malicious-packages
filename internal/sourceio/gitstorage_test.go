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

package sourceio_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/ossf/malicious-packages/internal/sourceio"
)

func TestGitStorage_Walk(t *testing.T) {
	dir := t.TempDir()

	r, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit() = %v; want no error", err)
	}

	w, err := r.Worktree()
	if err != nil {
		t.Fatalf("WorkTree() = %v; want no error", err)
	}

	files := map[string]string{
		"yes-file": "success",
		"no-file":  "fail",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile(%q) = %v; want no error", name, err)
		}
		if _, err := w.Add(name); err != nil {
			t.Fatalf("Add(%q) = %v; want no error", name, err)
		}
	}
	commitHash, err := w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{Name: "Test User", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("Commit() = %v; want no error", err)
	}

	s := &sourceio.GitStorage{
		Repository: dir,
		Branch:     "master",
	}
	prefix := "yes-"
	end, err := s.Walk(t.Context(), prefix, "", func(ctx context.Context, path string, r io.Reader) error {
		if !strings.HasPrefix(path, prefix) {
			t.Fatalf("path %q does not have prefix %q", path, prefix)
		}
		bytes, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll() = %v; want no error", err)
		}
		if got := string(bytes); got != "success" {
			t.Fatalf("Read %q; want %q", got, "success")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk() = %v; want no error", err)
	}
	want := commitHash.String()
	if end != want {
		t.Fatalf("Walk() = %q; want %q", end, want)
	}
}
