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
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/google/renameio"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"

	"github.com/ossf/malicious-packages/cmd/ingest/sourceio"
	"github.com/ossf/malicious-packages/cmd/ingest/startkeys"
	"github.com/ossf/malicious-packages/internal/config"
	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/malicious-packages/internal/reportio"
	"github.com/ossf/malicious-packages/internal/source"
)

var tempDir string

func main() {
	configFlag := flag.String("config", "", "the filepath to the YAML config file")
	startKeysFlag := flag.String("start-keys", "", "the filepath to a YAML file containing the keys to start from")
	sourceFlag := flag.String("source", "", "ingest files for the specified source only")
	localDirFlag := flag.String("dir", "", "ingest OSV reports from the given local dir. Requires -source.")
	flag.Parse()

	if *configFlag == "" {
		log.Fatalf("-config flag is required")
	}

	if *localDirFlag != "" && *sourceFlag == "" {
		log.Fatalf("-dir requires -source to be set")
	}

	lp, err := filepath.Abs(*localDirFlag)
	if err != nil {
		log.Fatalf("Failed finding absolute path of %s: %v", *localDirFlag, err)
	}
	if s, err := os.Stat(lp); os.IsNotExist(err) {
		log.Fatalf("-dir %s does not exist", *localDirFlag)
	} else if err != nil {
		log.Fatalf("-dir %s failed to stat: %v", *localDirFlag, err)
	} else if !s.IsDir() {
		log.Fatalf("-dir %s is not a directory", *localDirFlag)
	}

	// Read sources from config
	configFile, err := os.Open(*configFlag)
	if err != nil {
		log.Fatalf("Failed to open config file %s: %v", *configFlag, err)
	}
	c, err := config.ReadYAML(configFile)
	if err != nil {
		log.Fatalf("Failed reading config: %v", err)
	}

	// Determine sources based on flags
	var sources []*source.Source
	if *sourceFlag != "" {
		// Attempt to find an existing source
		var src *source.Source
		for _, s := range c.Sources {
			if s.ID == *sourceFlag {
				src = s
				break
			}
		}
		// Override the source bucket and prefix with a file:// handler so the
		// local files are consumed instead.
		if *localDirFlag != "" {
			if src == nil {
				// For local files tolerate the non-existance of a source.
				src = &source.Source{
					ID:              *sourceFlag,
					LookbackEntries: 0,
				}
			}
			src.Bucket = fmt.Sprintf("file://%s", lp)
			src.Prefix = ""
		}
		if src == nil {
			log.Fatalf("Unknown source %s", *sourceFlag)
		}
		sources = append(sources, src)
	} else {
		sources = c.Sources
	}

	log.Printf("Using config: id prefix=%s, malicious=%s, false positives=%s, sources=%d", c.IDPrefix, c.MaliciousPath, c.FalsePositivePath, len(sources))

	keys, err := loadStartKeys(*startKeysFlag)
	if err != nil {
		log.Fatalf("Failed loading start keys: %v", err)
	}

	// Create a temp directory for atomic writes. We use the system temp
	// directory to avoid accidentally leaving temp junk in the repository.
	tempDir, err = os.MkdirTemp("", "osv-ingest-*")
	if err != nil {
		log.Fatalf("Failed creating temp dir: %v", err)
	}
	defer func() {
		// Clean up temp directory
		if err := os.RemoveAll(tempDir); err != nil {
			log.Fatalf("Failed cleaning up temp dir: %v", err)
		}
	}()

	ctx := context.Background()
	for _, s := range sources {
		end, err := ingestReports(ctx, s, c, keys.Get(s.ID))
		if err != nil {
			// Abort here since the repo is now in a dirty state.
			log.Fatalf("Failed to ingest reports for source %s: %v", s.ID, err) //nolint:gocritic
		}
		keys.Set(s.ID, end)
	}

	// Atomically write updated start keys...
	if err := saveStartKeys(*startKeysFlag, keys); err != nil {
		log.Fatalf("Failed saving start keys: %v", err)
	}
}

func ingestReports(ctx context.Context, s *source.Source, c *config.Config, start string) (string, error) {
	log.Printf("[%s] Processing... (bucket: %s, prefix: %s)", s.ID, s.Bucket, s.Prefix)
	saveCount := 0
	end, err := sourceio.Walk(ctx, s, start, func(ctx context.Context, key string, rdr io.Reader) error {
		// Generate a hash while we consume the report so we can detect duplicates.
		h := sha256.New()
		rdr = io.TeeReader(rdr, h)

		r, err := report.ReadJSON(rdr)
		if err != nil {
			return fmt.Errorf("failed parsing report: %w", err)
		}
		log.Printf("[%s] Found report: %s (%s) - %s", s.ID, r.Name, r.Ecosystem, key)

		shasum := fmt.Sprintf("%x", h.Sum(nil))

		// Ensure the location where the OSV is going to be stored is safe.
		path := r.Path()
		if err := reportio.ValidatePath(path); err != nil {
			return fmt.Errorf("failed to validate destination: %w", err)
		}

		// Check if the origin has already been ingested.
		if ok, err := reportio.OriginExistsInPaths(path, c.Paths(), s.ID, shasum); err != nil {
			return fmt.Errorf("duplicate detection failed: %w", err)
		} else if ok {
			log.Printf("[%s]   skipping, already imported.", s.ID)
			return nil
		}

		// Add the origin to the report so we can de-dupe in the future and
		// track where and when the report was ingested.
		r.AddOrigin(s.ID, shasum)

		// Prepare the destination path, creating it if needed.
		dest := filepath.Clean(filepath.Join(c.MaliciousPath, path))
		log.Printf("[%s]   dest = %s", s.ID, dest)
		if err := os.MkdirAll(dest, 0o777); err != nil {
			return fmt.Errorf("failed to create destination: %w", err)
		}

		// Create the local file and write it
		filename := generateUnassignedFilename(c.IDPrefix, s.ID, shasum, "json")
		log.Printf("[%s]   file = %s", s.ID, filename)
		fp := filepath.Join(dest, filename)
		// Use renameio to generate a temp file in tempDir that is atomically
		// moved into place after. This is not safe for concurrent use.
		t, err := renameio.TempFile(tempDir, fp)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", fp, err)
		}
		defer t.Cleanup()
		err = r.WriteJSON(t)
		if err != nil {
			return fmt.Errorf("failed to write %s: %w", fp, err)
		}
		if err := t.CloseAtomicallyReplace(); err != nil {
			return fmt.Errorf("atomic save failed: %w", err)
		}
		saveCount++
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed walking source %s: %w", s.ID, err)
	}
	if saveCount == 0 {
		log.Printf("[%s] No reports imported.", s.ID)
		// Return the start key as the end key if there were no records imported
		// so we *always* start at the same position next time.
		return start, nil
	}
	log.Printf("[%s] %d report(s) imported. New start key: %s", s.ID, saveCount, end)
	return end, nil
}

func generateUnassignedFilename(prefix, sourceID, shasum, ext string) string {
	return fmt.Sprintf("%s-0000-%s-%s.%s", prefix, sourceID, shasum[:16], ext)
}

func loadStartKeys(filename string) (*startkeys.StartKeys, error) {
	if filename == "" {
		return nil, nil
	}
	sk := startkeys.New()
	f, err := os.Open(filename)
	if os.IsNotExist(err) {
		// State file doesn't exist yet, so just use the default.
		return sk, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed reading start keys: %w", err)
	}
	if err := sk.ReadYAML(f); err != nil {
		return nil, fmt.Errorf("failed parsing: %w", err)
	}
	return sk, nil
}

func saveStartKeys(filename string, keys *startkeys.StartKeys) error {
	if filename == "" {
		return nil
	}
	if !keys.IsDirty() {
		return nil
	}
	log.Printf("Saving new start keys: %#v", keys)
	t, err := renameio.TempFile(tempDir, filename)
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}
	defer t.Cleanup()
	if err := keys.WriteYAML(t); err != nil {
		return fmt.Errorf("failed writing to file: %w", err)
	}
	if err := t.CloseAtomicallyReplace(); err != nil {
		return fmt.Errorf("failed atomically writing file: %w", err)
	}
	return nil
}
