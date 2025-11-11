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

package sourceio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

const defaultGitBranch = "main"

type GitStorage struct {
	Repository string `yaml:"repository"`
	Branch     string `yaml:"branch"`
}

// StorageType implements the Storage interface.
func (s *GitStorage) StorageType() StorageType {
	return StorageTypeGit
}

// String implements the Storage interface.
func (s *GitStorage) String() string {
	return fmt.Sprintf("git: '%s - %s'", s.Repository, s.Branch)
}

// Walk implements the Storage interface.
func (s *GitStorage) Walk(ctx context.Context, prefix, start string, walkFn WalkFunc) (string, error) {
	if s.Repository == "" {
		return "", fmt.Errorf("no repository specified")
	}
	if s.Branch == "" {
		s.Branch = defaultGitBranch
	}

	// Clone the supplied repository into memory.
	repo, err := git.CloneContext(ctx, memory.NewStorage(), nil, &git.CloneOptions{
		URL:           s.Repository,
		ReferenceName: plumbing.NewBranchReferenceName(s.Branch),
		SingleBranch:  true,
		Tags:          git.NoTags,
	})
	if err != nil {
		return "", fmt.Errorf("failed cloning '%s - %s': %w", s.Repository, s.Branch, err)
	}

	// Get the branch's HEAD ref.
	ref, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed getting head: %w", err)
	}

	// Retrieve the HEAD commit's object from the repository so we can
	// both retrieve the files at HEAD, and diff against "start" if it is set.
	headCommit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return "", fmt.Errorf("Failed getting head commit object: %w", err)
	}

	tree, err := headCommit.Tree()
	if err != nil {
		return "", fmt.Errorf("failed getting head tree: %w", err)
	}

	var files iter.Seq[string] = nil
	if start != "" {
		// We have a starting commit, so grab the commit object so we can
		// diff against the HEAD commit.
		startCommit, err := repo.CommitObject(plumbing.NewHash(start))
		if err != nil {
			// TODO: consider falling back to treeIterator if we have an error.
			return "", fmt.Errorf("Failed getting %q commit object: %w", start, err)
		}

		// Determine the files that were added or modified since "start".
		files, err = deltaFileIterator(ctx, startCommit, headCommit, repo)
		if err != nil {
			return "", fmt.Errorf("delta iterator: %w", err)
		}
	} else {
		// By default just parse the entire tree at HEAD.
		files = treeIterator(tree)
	}

	for filename := range files {
		if !strings.HasPrefix(filename, prefix) {
			continue
		}
		file, err := tree.File(filename)
		if err != nil {
			return "", fmt.Errorf("failed finding object %q: %w", filename, err)
		}
		r, err := file.Reader()
		if err != nil {
			return "", fmt.Errorf("failed creating reader %q: %w", filename, err)
		}
		err = walkFn(ctx, filename, r)
		// Call close immediately on the reader to free up the resources. Using
		// defer would cause the reader to remain open until the function returns.
		r.Close()
		if err != nil {
			return "", err
		}
	}
	return ref.Hash().String(), nil
}

func deltaFileIterator(ctx context.Context, from, to *object.Commit, repo *git.Repository) (iter.Seq[string], error) {
	patch, err := from.PatchContext(ctx, to)
	if err != nil {
		return nil, fmt.Errorf("failed calculating patch: %w", err)
	}

	return func(yield func(string) bool) {
		for _, filePatch := range patch.FilePatches() {
			_, to := filePatch.Files()
			if to == nil {
				// A file was deleted. We don't need to process this change.
				// Although we may want to fail in the future.
				continue
			}
			if !yield(to.Path()) {
				return
			}
		}
	}, nil
}

func treeIterator(tree *object.Tree) iter.Seq[string] {
	files := tree.Files()
	return func(yield func(string) bool) {
		for {
			next, err := files.Next()
			if errors.Is(err, io.EOF) {
				return
			} else if err != nil {
				// Not sure when this would happen...
				panic(err)
			}
			if !yield(next.Name) {
				return
			}
		}
	}
}
