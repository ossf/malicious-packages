// Copyright 2022 Malicious Packages Authors
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

package reportio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ossf/malicious-packages/cmd/ingest/report"
)

var (
	ErrPathNotLocal         = errors.New("report path is not local")
	ErrInvalidPathStructure = errors.New("invalid report path structure")
)

// ValidatePath ensures path is a valid place to put OSV reports.
//
// This method enforces that every path is local, and that it has at least two
// path elements - i.e. an ecosystem, and a package name.
func ValidatePath(path string) error {
	if !filepath.IsLocal(path) {
		return ErrPathNotLocal
	}
	path = filepath.Dir(filepath.Dir(filepath.Join("local", filepath.Clean(path))))
	if path == "" || path == "." {
		return ErrInvalidPathStructure
	}
	return nil
}

// OriginExistsInPaths returns true if an OSV report exists with an origin that
// exists with the same sourceID and shasum.
//
// The function will iterate across each of the base paths in bases and join
// them with path using `filepath.Join(base, path)`.
//
// An error will be returned if there is an error reading the OSV reports, or
// the filesystem.
func OriginExistsInPaths(path string, bases []string, sourceID, shasum string) (bool, error) {
	for _, base := range bases {
		fp := filepath.Clean(filepath.Join(base, path))
		uniq, err := originExistsInPath(fp, sourceID, shasum)
		if err != nil {
			return false, err
		}
		if uniq {
			return true, nil
		}
	}
	// No bases, so no origins can exist.
	return false, nil
}

func originExistsInPath(path, sourceID, shasum string) (bool, error) {
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		// path doesn't exist, so there is no origin here.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read dir %s: %w", path, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			// skip subdirectories
			continue
		}
		n := filepath.Join(path, entry.Name())
		f, err := os.Open(n)
		if err != nil {
			return false, fmt.Errorf("failed to open %s: %w", n, err)
		}

		r, err := report.ReadJSON(f)
		f.Close()
		if err != nil {
			return false, fmt.Errorf("failed to parse %s: %w", n, err)
		}

		if r.HasOrigin(sourceID, shasum) {
			return true, nil
		}
	}
	// We looked at every entry, and reached here, so no origins exists.
	return false, nil
}
