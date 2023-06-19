package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/renameio"
	"github.com/ossf/malicious-packages/internal/config"
	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/malicious-packages/internal/reportio"
)

var tempDir string

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

	if err := preprocessRepo(c); err != nil {
		log.Fatalf("Failed to preprocess repo: %v", err)
	}
}

func preprocessRepo(c *config.Config) error {
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
		reports, err := reportio.ReportsInPaths(p, c.Paths())
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
		if len(noIDs) == 0 {
			// All IDs are assigned
			return nil
		}
		if len(withIDs) > 1 {
			// If there is more than one reports with an ID then our assumption
			// that there is only a signle OSV per package is wrong.
			return fmt.Errorf("multiple reports with IDs in %s", p)
		}

		var basis string
		var toMerge []string
		if len(withIDs) == 1 {
			basis = withIDs[0]
			toMerge = noIDs
		} else {
			basis = noIDs[0]
			toMerge = noIDs[1:]
		}

		return processReports(p, basis, toMerge)
	}))
	return err
}

func hasID(prefix, name string) bool {
	base := filepath.Base(name)
	return !strings.HasPrefix(base, fmt.Sprintf("%s-0000-", prefix))
}

func processReports(path, dest string, mergeSrcs []string) error {
	log.Printf("Processing %s", path)
	log.Printf("  dest = %s", dest)

	destReport, err := report.FromFile(dest)
	if err != nil {
		return fmt.Errorf("failed loading dest %s: %w", dest, err)
	}

	// Ensure the base report is always normalized.
	log.Printf("  normalizing %s", filepath.Base(dest))
	if err := destReport.Normalize(); err != nil {
		return fmt.Errorf("failed normalizing %s: %w", dest, err)
	}

	for _, src := range mergeSrcs {
		log.Printf("  merging %s", filepath.Base(src))

		srcReport, err := report.FromFile(src)
		if err != nil {
			return fmt.Errorf("failed loading src %s: %w", src, err)
		}

		if err := destReport.Merge(srcReport); err != nil {
			return fmt.Errorf("failed to merge %s: %w", src, err)
		}
	}

	// Save the destination report atomically to avoid any corruption.
	t, err := renameio.TempFile(tempDir, dest)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", dest, err)
	}
	defer t.Cleanup()
	err = destReport.WriteJSON(t)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", dest, err)
	}
	if err := t.CloseAtomicallyReplace(); err != nil {
		return fmt.Errorf("atomic save failed: %w", err)
	}

	// Clean up all the files that we merged.
	for _, src := range mergeSrcs {
		if err := os.Remove(src); err != nil {
			return fmt.Errorf("failed to remove %s: %w", src, err)
		}
	}

	return nil
}
