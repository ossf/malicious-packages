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

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/renameio"

	"github.com/ossf/malicious-packages/internal/config"
	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/malicious-packages/internal/reportio"
)

var tempDir string

func main() {
	configFlag := flag.String("config", "", "the filepath to the YAML config file")
	abortUnmergableFlag := flag.Bool("abort-unmergable", false, "abort if unmergable reports encountered")
	flag.Parse()

	if *configFlag == "" {
		log.Fatalf("-config flag is required")
	}

	// read sources from config
	configFile, err := os.Open(*configFlag)
	if err != nil {
		log.Fatalf("Failed to open config file %s: %v", *configFlag, err)
	}
	c, err := config.ReadYAML(configFile)
	if err != nil {
		log.Fatalf("Failed reading config: %v", err)
	}

	// Create a temp directory for atomic writes. We use the system temp
	// directory to avoid accidentally leaving temp junk in the repository.
	tempDir, err = os.MkdirTemp("", "osv-merge-*")
	if err != nil {
		log.Fatalf("Failed creating temp dir: %v", err)
	}
	defer func() {
		// Clean up temp directory
		if err := os.RemoveAll(tempDir); err != nil {
			log.Fatalf("Failed cleaning up temp dir: %v", err)
		}
	}()

	if err := preprocessRepo(c, *abortUnmergableFlag); err != nil {
		log.Fatalf("Failed to preprocess repo: %v", err) //nolint:gocritic
	}
}

func preprocessRepo(c *config.Config, abortUnmergable bool) error {
	err := filepath.WalkDir(c.MaliciousPath, fs.WalkDirFunc(func(path string, info fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return filepath.SkipDir
		} else if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		p, err := filepath.Rel(c.MaliciousPath, path)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}
		reports, err := reportio.ReportsInPaths(p, c.ActivePaths())
		if err != nil {
			return fmt.Errorf("failed getting reports: %w", err)
		}
		if len(reports) == 0 {
			// No reports means there is no work to be done.
			return nil
		}
		var noIDs []string
		var withIDs []string
		for _, n := range reports {
			if hasID(c.IDPrefix, n) {
				withIDs = append(withIDs, n)
			} else {
				noIDs = append(noIDs, n)
			}
		}
		if n := len(withIDs); n > 1 {
			// If there is more than one reports with an ID then our assumption
			// that there is only a single OSV per package is wrong.
			return fmt.Errorf("%d reports with IDs in %s (%v)", n, p, withIDs)
		}
		if len(noIDs) == 0 {
			// All IDs are assigned
			return nil
		}

		var existing string
		if len(withIDs) == 1 {
			existing = withIDs[0]
		}

		unmergable, err := processReports(p, existing, noIDs)
		if err != nil {
			return err
		}
		if total := len(unmergable); abortUnmergable && total > 0 {
			return fmt.Errorf("%d unmergable report(s) are present", total)
		}
		for _, report := range unmergable {
			err := reportio.MoveReport(report, c.MaliciousPath, c.UnmergablePath)
			if err != nil {
				return err
			}
		}
		return nil
	}))
	return err
}

func hasID(prefix, name string) bool {
	base := filepath.Base(name)
	return !strings.HasPrefix(base, fmt.Sprintf("%s-0000-", prefix))
}

func processReports(path, existing string, new []string) ([]string, error) {
	log.Printf("Processing %s", path)

	var dest string
	var destReport *report.Report

	// If we have an existing report, load it first. It should always be valid
	// so we abort if the existing report has any issues.
	if existing != "" {
		log.Printf("  reading existing = %s", existing)
		r, err := report.FromFile(existing)
		if err != nil {
			return nil, fmt.Errorf("failed loading existing %s: %w", existing, err)
		}

		// Any existing report should already be normalized, and this should not fail.
		// If it does we have a problem.
		log.Printf("    normalizing %s", filepath.Base(existing))
		if err := r.Normalize(); err != nil {
			return nil, fmt.Errorf("failed normalizing existing %s: %w", existing, err)
		}
		dest = existing
		destReport = r
	}

	var unmergable []string
	newReports := map[string]*report.Report{}

	// markUnmergable is a helper to make it easy to add a filename to the
	// set of unmergable reports, and remove the entry from newReports if it is
	// present.
	markUnmergable := func(message string, fps ...string) {
		unmergable = append(unmergable, fps...)
		for _, fp := range fps {
			delete(newReports, fp)
		}
		log.Printf("    %s, skipping %s", message, strings.Join(fps, ", "))
	}

	// Load each new report one by one. If the report has any non-filesystem
	// based issues (i.e. only json parsing, or report validation issues) then
	// we move aside the report.
	for _, p := range new {
		log.Printf("  reading new = %s", p)
		r, err := report.FromFile(p)
		var jsonSyntaxError *json.SyntaxError
		var jsonUmarshalTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonSyntaxError) ||
			errors.As(err, &jsonUmarshalTypeError) ||
			errors.Is(err, report.ErrInvalidOSV) ||
			errors.Is(err, report.ErrUnexpectedOSV) ||
			errors.Is(err, report.ErrInvalidDetails) {
			markUnmergable(fmt.Sprintf("failed reading report: %v", err), p)
			continue
		} else if err != nil {
			return nil, fmt.Errorf("failed normalizing existing %s: %w", existing, err)
		}

		// If we did not load a dest earlier, try and choose one now from the
		// new reports.
		if destReport == nil {
			// Attempt to normalize this report and make it the destReport. If
			// this fails we can try the next and move aside the current one.
			log.Printf("    normalizing %s", filepath.Base(p))
			if err := r.Normalize(); errors.Is(err, report.ErrNormalizing) {
				markUnmergable(fmt.Sprintf("failed normalizing: %v", err), p)
				continue
			} else if err != nil {
				return nil, fmt.Errorf("failed normalizing %w", err)
			}
			destReport = r
			dest = p
		} else {
			newReports[p] = r
		}
	}

	// Either "existing" should have been set, or we chose a destination report
	// from the set of "new" reports. If this is not the case, then we abort.
	if destReport == nil || dest == "" {
		log.Printf("  dest = no mergable report found in %s, aborting", path)
		return unmergable, nil
	}
	log.Printf("  dest = %s", dest)

	if destReport.IsWithdrawn() && destReport.ID() == "" {
		if len(newReports) == 0 {
			// The destination is new and withdrawn and we aren't merging with
			// any other reports, so remove the report because we don't already
			// redacted reports.
			// NOTE: this may cause the same withdrawn report to be ingested and
			// ignored repeated times, as the origin information is lost when
			// the report is deleted. We may eventually decide to keep reports
			// even if they are withdrawn.
			if err := os.Remove(dest); err != nil {
				return nil, fmt.Errorf("failed to remove %s: %w", dest, err)
			}
			return unmergable, nil
		}
		// TODO: implement withdrawn behaviour
		markUnmergable("merging new withdrawn reports is currently unsupported", append(slices.Collect(maps.Keys(newReports)), dest)...)
		return unmergable, nil
	}

	for src, srcReport := range newReports {
		log.Printf("  merging %s", filepath.Base(src))

		if srcReport.IsWithdrawn() {
			markUnmergable("merging new withdrawn reports is currently unsupported", src)
			continue
		}

		if err := destReport.Merge(srcReport); errors.Is(err, report.ErrMergeFailure) || errors.Is(err, report.ErrNormalizing) {
			markUnmergable(fmt.Sprintf("failed to merge: %v", err), src)
			continue
		} else if err != nil {
			return nil, fmt.Errorf("failed to merge %w", err)
		}
	}

	// Save the destination report atomically to avoid any corruption.
	t, err := renameio.TempFile(tempDir, dest)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", dest, err)
	}
	defer t.Cleanup()
	err = destReport.WriteJSON(t)
	if err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", dest, err)
	}
	if err := t.CloseAtomicallyReplace(); err != nil {
		return nil, fmt.Errorf("atomic save failed: %w", err)
	}

	// Clean up all the files that we merged.
	if err := removeFiles(slices.Collect(maps.Keys(newReports))); err != nil {
		return nil, fmt.Errorf("failed removing merged files: %w", err)
	}

	return unmergable, nil
}

func removeFiles(files []string) error {
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			return fmt.Errorf("remove %q: %w", file, err)
		}
	}
	return nil
}
