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

package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ossf/malicious-packages/internal/config"
	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/malicious-packages/internal/reportio"
)

func main() {
	csvFlag := flag.String("csv", "stats.csv", "the filepath to write the CSV file")
	jsonFlag := flag.String("json", "", "the filepath to write the JSON file")
	configFlag := flag.String("config", "", "the filepath to the YAML config file")
	flag.Parse()

	if *csvFlag == "" && *jsonFlag == "" {
		log.Fatalf("-csv or -json flag is required")
	}

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

	log.Println("Processing OSV files...")
	// ecosystem -> month -> count
	stats := make(map[string]map[string]int)
	if err := processRepo(c, stats); err != nil {
		log.Fatalf("Failed to process repo: %v", err)
	}

	if *csvFlag != "" {
		log.Printf("Writing CSV to %s...", *csvFlag)
		if err := writeCSV(*csvFlag, stats); err != nil {
			log.Fatalf("Failed to write CSV: %v", err)
		}
	}
	if *jsonFlag != "" {
		log.Printf("Writing JSON to %s...", *jsonFlag)
		if err := writeJSON(*jsonFlag, stats); err != nil {
			log.Fatalf("Failed to write JSON: %v", err)
		}
	}

	log.Println("Done.")
}

func formatMonth(t time.Time) string {
	date := t.UTC().Format("2006-01-02")
	return date[:7] + "-01"
}

// hasID returns true if base starts with "{prefix}-", but does not start with
// "{prefix}-0000-". This ensures only reports with IDs assigned are included
// in stats.
func hasID(prefix, base string) bool {
	return strings.HasPrefix(base, fmt.Sprintf("%s-", prefix)) && !strings.HasPrefix(base, fmt.Sprintf("%s-0000-", prefix))
}

func processRepo(c *config.Config, stats map[string]map[string]int) error {
	err := filepath.WalkDir(c.MaliciousPath, fs.WalkDirFunc(func(path string, info fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return filepath.SkipDir
		} else if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !reportio.IsPossibleReport(info.Name(), info.Type()) {
			return nil
		}
		if !hasID(c.IDPrefix, info.Name()) {
			// Skip any file that doesn't match our ID pattern.
			return nil
		}
		return processReport(path, stats)
	}))
	return err
}

func processReport(path string, stats map[string]map[string]int) error {
	log.Printf("Processing %s", path)

	r, err := report.FromFile(path)
	if err != nil {
		return fmt.Errorf("failed loading report %s: %w", path, err)
	}
	ecosystem := r.Ecosystem
	month := formatMonth(r.Published())

	if _, ok := stats[ecosystem]; !ok {
		stats[ecosystem] = make(map[string]int)
	}
	stats[ecosystem][month]++

	return nil
}

func writeJSON(path string, stats map[string]map[string]int) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(stats); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

func writeCSV(path string, stats map[string]map[string]int) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"ecosystem", "month", "published reports"}); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	ecosystems := slices.Sorted(maps.Keys(stats))
	for _, eco := range ecosystems {
		months := slices.Sorted(maps.Keys(stats[eco]))
		for _, month := range months {
			count := stats[eco][month]
			row := []string{
				eco,
				month,
				strconv.Itoa(count),
			}
			if err := w.Write(row); err != nil {
				return fmt.Errorf("failed to write row: %w", err)
			}
		}
	}

	return nil
}
