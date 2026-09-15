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

package reportargs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ossf/malicious-packages/internal/reportio"
)

type ResolverFlags int

const (
	ResolveByFile ResolverFlags = 1 << iota
	ResolveByDirectory
	ResolveByEcosystemAndName
	ResolveByID
)

const (
	AllResolvers = ResolveByFile | ResolveByDirectory | ResolveByEcosystemAndName | ResolveByID
)

type reportResolveFunc func(paths, bases []string) (map[string][]string, []string, error)

// resolvers are the valid set of report resolver funcs. They must correspond to
// the ResolverFlags above exactly, and appear in the same order.
//
// The resolvers are configured using flags, rather than function refs because
// the order the resolvers are run in is important. They are ordered from the
// least expensive to the most expensive to run - `byReportFile` only considers
// a single file, and `byID` walks each specified base.
var resolvers = []resolver{
	{
		flag:    ResolveByFile,
		fn:      byReportFile,
		name:    "File",
		argName: "filename",
	},
	{
		flag:    ResolveByDirectory,
		fn:      byDirectoryPath,
		name:    "Directory",
		argName: "dirname",
	},
	{
		flag:    ResolveByEcosystemAndName,
		fn:      byEcosystemAndPackage,
		name:    "Ecosystem and Package",
		argName: "ecosystem/package",
	},
	{
		flag:    ResolveByID,
		fn:      byID,
		name:    "Report ID",
		argName: "report_id",
	},
}

type resolver struct {
	flag    ResolverFlags
	fn      reportResolveFunc
	name    string
	argName string
}

func (r resolver) IsEnabled(flag ResolverFlags) bool {
	return r.flag&flag != 0
}

func (r resolver) Resolve(paths, bases []string) (map[string][]string, []string, error) {
	return r.fn(paths, bases)
}

func byID(candidates, bases []string) (map[string][]string, []string, error) {
	var ids []string
	var unused []string
	for _, c := range candidates {
		if strings.ContainsRune(c, filepath.Separator) {
			unused = append(unused, c)
		} else {
			ids = append(ids, c)
		}
	}

	if len(ids) == 0 {
		// This function is expensive, so abort if there is no work to do.
		return nil, unused, nil
	}

	var found []string
	reports := make(map[string][]string)
	for _, base := range bases {
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if len(ids) == len(found) {
				// If we have found all the reports stop immediately.
				return filepath.SkipAll
			}
			if d.IsDir() {
				// Skip if d is a directory.
				return nil
			}
			if !reportio.IsPossibleReport(d.Name(), d.Type()) {
				return nil
			}

			dir, filename := filepath.Split(path)
			// Get the name minus the extension, which should be the ID.
			name := strings.TrimSuffix(filename, filepath.Ext(filename))
			if slices.Contains(ids, name) {
				rel, err := filepath.Rel(base, dir)
				if err != nil {
					return fmt.Errorf("failed to get relative path for %q: %w", dir, err)
				}
				found = append(found, name)
				reports[rel] = append(reports[rel], path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	// Stick all the unfound ids into the unused bucket.
	if len(found) != len(ids) {
		for _, id := range ids {
			if !slices.Contains(found, id) {
				unused = append(unused, id)
			}
		}
	}
	return reports, unused, nil
}

func byEcosystemAndPackage(candidates, bases []string) (map[string][]string, []string, error) {
	var unused []string
	reports := make(map[string][]string)

	for _, c := range candidates {
		if !strings.ContainsRune(c, filepath.Separator) {
			// Expect at least one slash in the candidate.
			unused = append(unused, c)
			continue
		}
		if err := reportio.ValidatePath(c); err != nil {
			// Do more validation on the path, and skip if it failed.
			unused = append(unused, c)
			continue
		}
		paths, err := reportio.ReportsInPaths(c, bases)
		if err != nil {
			return nil, nil, fmt.Errorf("failed getting reports for %q: %w", c, err)
		}
		if len(paths) == 0 {
			// No reports in this path.
			unused = append(unused, c)
			continue
		}
		reports[c] = append(reports[c], paths...)
	}
	return reports, unused, nil
}

func byDirectoryPath(candidates, bases []string) (map[string][]string, []string, error) {
	var unused []string
	reports := make(map[string][]string)

	for _, c := range candidates {
		if !strings.ContainsRune(c, filepath.Separator) {
			// Expect at least one slash in the candidate.
			unused = append(unused, c)
			continue
		}
		info, err := os.Stat(c)
		if os.IsNotExist(err) {
			// Expect the directory to exist.
			unused = append(unused, c)
			continue
		} else if err != nil {
			// Some other error occurred.
			return nil, nil, fmt.Errorf("failed to stat %q: %w", c, err)
		}
		if !info.IsDir() {
			// Expect the directory to actually be a directory.
			unused = append(unused, c)
			continue
		}
		dir, err := filepath.Abs(c)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get absolute path for %q: %w", c, err)
		}

		relPath := ""
		for _, base := range bases {
			rel, err := filepath.Rel(base, dir)
			if err == nil && !strings.HasPrefix(filepath.ToSlash(rel), "../") {
				relPath = rel
				break
			}
		}
		if relPath == "" {
			// Expect a relative path to a base.
			unused = append(unused, c)
			continue
		}

		paths, err := reportio.ReportsInPaths(dir, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed getting reports for %q: %w", c, err)
		}
		if len(paths) == 0 {
			// No reports in this path.
			unused = append(unused, c)
			continue
		}
		reports[relPath] = append(reports[relPath], paths...)
	}
	return reports, unused, nil
}

func byReportFile(candidates, bases []string) (map[string][]string, []string, error) {
	var unused []string
	reports := make(map[string][]string)

	for _, c := range candidates {
		if !strings.ContainsRune(c, filepath.Separator) {
			// Expect at least one slash in the candidate.
			unused = append(unused, c)
			continue
		}
		info, err := os.Stat(c)
		if os.IsNotExist(err) {
			// Expect the directory to exist.
			unused = append(unused, c)
			continue
		} else if err != nil {
			// Some other error occurred.
			return nil, nil, fmt.Errorf("failed to stat %q: %w", c, err)
		}
		if !info.Mode().IsRegular() {
			// Expect the file to actually be a file.
			unused = append(unused, c)
			continue
		}
		if !reportio.IsPossibleReport(info.Name(), info.Mode()) {
			// Expect the file to be a possible report.
			unused = append(unused, c)
			continue
		}
		filename, err := filepath.Abs(c)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get absolute path for %q: %w", c, err)
		}

		relFilename := ""
		for _, base := range bases {
			rel, err := filepath.Rel(base, filename)
			if err == nil && !strings.HasPrefix(filepath.ToSlash(rel), "../") {
				relFilename = rel
				break
			}
		}
		if relFilename == "" {
			// Expect a relative path to a base.
			unused = append(unused, c)
			continue
		}
		relPath := filepath.Dir(relFilename)
		reports[relPath] = append(reports[relPath], filename)
	}
	return reports, unused, nil
}
