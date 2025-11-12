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

// The package sourceio makes it easy to process OSV reports from their data
// sources, such as cloud blob stores (e.g. AWS S3, Google Cloud Storage) and
// git repositories.
package sourceio

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// ErrInvalidStorage is returned when umarshaling StorageWrapper as YAML fails.
// Use errors.Is(err, ErrInvalidStorage) to tests for this error.
var ErrInvalidStorage = errors.New("invalid source storage")

// WalkFunc is called by Walk for each matching path seen in the storage.
// The value of "path" will depend on the underlying storage.
type WalkFunc func(ctx context.Context, path string, r io.Reader) error

// Storage provides a simple interface for iterating across a collection of
// source OSV reports.
type Storage interface {
	// Open storage for walking. Must be called before Walk.
	Open(ctx context.Context) error

	// Close storage after use to free up resources.
	Close() error

	// StorageType identifies what the type of storage being used.
	StorageType() StorageType

	// Walk iterates through the entries in the source storage and calls walkFn
	// for each path starting with prefix with a reader for consuming the entry.
	//
	// If start is not empty, entries will be consumed from start.
	Walk(ctx context.Context, prefix, start string, walkFn WalkFunc) (string, error)

	// Storage implementations must also implement the Stringer interface.
	fmt.Stringer
}
