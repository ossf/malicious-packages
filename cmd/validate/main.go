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
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/malicious-packages/internal/config"
	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/malicious-packages/internal/reportio"
)

const (
	validExt = ".json"
)

var validIDRe = regexp.MustCompile(`^([A-Z]+)-[0-9]{4}-[0-9]+$`)

func main() {
	configFlag := flag.String("config", "", "the filepath to the YAML config file")
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

	if err := validateRepo(c); err != nil {
		log.Fatalf("Validation failed: %v", err)
	}
}

func validateRepo(c *config.Config) error {
	for _, b := range c.Paths() {
		if err := validateBase(b, c.IDPrefix); err != nil {
			return err
		}
	}
	return nil
}

func validateBase(basePath, idPrefix string) error {
	log.Printf("Validating %s", basePath)
	return filepath.WalkDir(basePath, fs.WalkDirFunc(func(path string, info fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return filepath.SkipDir
		} else if err != nil {
			return err
		}
		if !reportio.IsPossibleReport(info.Name(), info.Type()) {
			return nil
		}

		return validateReport(path, basePath, idPrefix)
	}))
}

func validateReport(reportPath, basePath, idPrefix string) error {
	dir, basename := filepath.Split(reportPath)
	ext := filepath.Ext(reportPath)
	fileID := strings.TrimSuffix(basename, ext)

	gotPath, err := filepath.Rel(basePath, dir)
	if err != nil {
		return fmt.Errorf("relative path: %w", err)
	}
	log.Printf("  - %s", filepath.Join(gotPath, basename))

	r, err := report.FromFile(reportPath)
	if err != nil {
		return fmt.Errorf("failed loading report %s: %w", reportPath, err)
	}
	id := r.ID()

	// Ensure the ID in the report corresponds to the name of the file.
	if id != "" && id != fileID {
		return fmt.Errorf("report filename %s does not match ID %s", basename, id)
	}
	if id != "" && !isIDValid(id, idPrefix) {
		return fmt.Errorf("id %s is not valid", id)
	}
	if id == "" && !isNewReportNameValid(fileID, idPrefix) {
		return fmt.Errorf("report name %s is not valid", fileID)
	}

	// Ensure the path is still valid, and the report file is in the correct
	// location.
	wantPath := r.Path()
	if err := reportio.ValidatePath(wantPath); err != nil {
		return fmt.Errorf("failed to validate destination: %w", err)
	}
	if wantPath != gotPath {
		return fmt.Errorf("report path %s does not match expected path %s", gotPath, wantPath)
	}

	// Ensure the extension is valid.
	if ext != validExt {
		return fmt.Errorf("report filename %s does not end with %s", basename, validExt)
	}

	// TODO: add "withdrawn" check for files in the false positives directory.

	return nil
}

func isIDValid(id, idPrefix string) bool {
	matches := validIDRe.FindStringSubmatch(id)
	if matches == nil {
		return false
	}
	return matches[1] == idPrefix
}

func isNewReportNameValid(name, idPrefix string) bool {
	return strings.HasPrefix(name, idPrefix+"-0000-")
}
