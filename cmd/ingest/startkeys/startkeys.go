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

package startkeys

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// StartKeys maps each source ID and prefix to the key that ingestion will start
// from.
//
// A nil value of StartKeys supports Get, Set and IsDirty, but have no effect.
type StartKeys struct {
	keys  map[string]map[string]string
	dirty bool
}

// New creates a new instance of StartKeys.
func New() *StartKeys {
	return &StartKeys{keys: make(map[string]map[string]string)}
}

// ReadYAML populates the data from the supplied reader containing YAML content.
func (sk *StartKeys) ReadYAML(r io.Reader) error {
	dec := yaml.NewDecoder(r)
	err := dec.Decode(&(sk.keys))
	if err != nil {
		return fmt.Errorf("failed decoding state yaml: %w", err)
	}
	return nil
}

// Get returns the corresponding start key for the supplied id and prefix. If
// the key is not present an empty string will be returned.
//
// An empty string will also be returned for a nil StartKeys.
func (sk *StartKeys) Get(id, prefix string) string {
	if sk == nil {
		return ""
	}
	if k, ok := sk.keys[id]; ok {
		return k[prefix]
	}
	return ""
}

// Set stores the key for the supplied id and prefix. If the key results in a
// value changing IsDirty() will return true.
//
// The function will no-op if StartKeys is nil.
func (sk *StartKeys) Set(id, prefix, key string) {
	if sk == nil {
		return
	}
	if key == "" {
		return
	}
	if _, ok := sk.keys[id]; !ok {
		sk.keys[id] = make(map[string]string)
	}
	if sk.keys[id][prefix] == key {
		return
	}
	sk.keys[id][prefix] = key
	sk.dirty = true
}

// IsDirty returns true if the internal state of the keys has changed, and
// requires persistence to storage.
//
// The function will always return false if StartKeys is nil.
func (sk *StartKeys) IsDirty() bool {
	if sk == nil {
		return false
	}
	return sk.dirty
}

// ToYAML serializes the keys to YAML and writes it to the supplied writer w.
func (sk *StartKeys) WriteYAML(w io.Writer) error {
	enc := yaml.NewEncoder(w)
	return enc.Encode(sk.keys)
}
