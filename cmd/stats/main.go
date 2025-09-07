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
	"os"
	"path/filepath"
	"strings"

	"github.com/ossf/malicious-packages/cmd/stats/collector"
	"github.com/ossf/malicious-packages/internal/config"
	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/malicious-packages/internal/reportio"
)

var dateGroupMap = map[string]struct {
	format string
	suffix string
}{
	"month": {
		format: "2006-01",
		suffix: "-01",
	},
	"year": {
		format: "2006",
		suffix: "-01-01",
	},
}

func main() {
	csvFlag := flag.String("csv", "stats.csv", "the filepath to write the CSV file")
	jsonFlag := flag.String("json", "", "the filepath to write the JSON file")
	configFlag := flag.String("config", "", "the filepath to the YAML config file")
	dateGroupFlag := flag.String("by-date", "month", "what granularity to group by date. Can be one of 'month', 'year', or empty to disable grouping")
	ecoGroupFlag := flag.Bool("by-ecosystem", true, "whether to group by ecosystem. Enabled by default")
	flag.Parse()

	if *csvFlag == "" && *jsonFlag == "" {
		log.Fatalf("-csv or -json flag is required")
	}

	cols := []string{}
	if *ecoGroupFlag {
		cols = append(cols, "ecosystem")
	}

	if *dateGroupFlag != "" {
		if _, ok := dateGroupMap[*dateGroupFlag]; !ok {
			log.Fatalf("-by-date must be either empty, 'month', or 'year'")
		}
		cols = append(cols, *dateGroupFlag)
	}
	dateGroup := dateGroupMap[*dateGroupFlag]
	reportCounts := collector.New("published reports", cols...)

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
	process := func(r *report.Report) {
		keys := []string{}
		if *ecoGroupFlag {
			keys = append(keys, r.Ecosystem)
		}
		if *dateGroupFlag != "" {
			keys = append(keys, r.Published().UTC().Format(dateGroup.format)+dateGroup.suffix)
		}
		reportCounts.Inc(keys...)
	}

	if err := processRepo(c, process); err != nil {
		log.Fatalf("Failed to process repo: %v", err)
	}

	if *csvFlag != "" {
		log.Printf("Writing CSV to %s...", *csvFlag)
		if err := writeCSV(*csvFlag, reportCounts.ForCSV()); err != nil {
			log.Fatalf("Failed to write CSV: %v", err)
		}
	}
	if *jsonFlag != "" {
		log.Printf("Writing JSON to %s...", *jsonFlag)
		if err := writeJSON(*jsonFlag, reportCounts.ForJSON()); err != nil {
			log.Fatalf("Failed to write JSON: %v", err)
		}
	}

	log.Println("Done.")
}

// hasID returns true if base starts with "{prefix}-", but does not start with
// "{prefix}-0000-". This ensures only reports with IDs assigned are included
// in stats.
func hasID(prefix, base string) bool {
	return strings.HasPrefix(base, fmt.Sprintf("%s-", prefix)) && !strings.HasPrefix(base, fmt.Sprintf("%s-0000-", prefix))
}

func processRepo(c *config.Config, process func(*report.Report)) error {
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
		return processReport(path, process)
	}))
	return err
}

func processReport(path string, process func(*report.Report)) error {
	log.Printf("Processing %s", path)

	r, err := report.FromFile(path)
	if err != nil {
		return fmt.Errorf("failed loading report %s: %w", path, err)
	}

	process(r)

	return nil
}

func writeJSON(path string, stats any) error {
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

func writeCSV(path string, stats [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	for _, row := range stats {
		if err := w.Write(row); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}
	return nil
}
