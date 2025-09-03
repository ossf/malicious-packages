// Copyright 2025 Malicious Packages Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Collector is used to help collect counts across zero or more dimensions.
type Collector struct {
	name   string
	dims   []string
	keys   []map[string]struct{}
	counts map[string]int
}

// New creates an instance of Collector for counting the named metric across
// the dimensions supplied in dims.
func New(name string, dims ...string) *Collector {
	c := &Collector{
		name:   name,
		dims:   dims,
		counts: make(map[string]int),
	}
	for range dims {
		c.keys = append(c.keys, make(map[string]struct{}))
	}
	return c
}

// Inc increments the count with each of the keys corresponding to the
// defined dimensions.
func (c *Collector) Inc(keys ...string) {
	for i, key := range keys {
		c.keys[i][key] = struct{}{}
	}
	c.counts[strings.Join(keys, ",")]++
}

func (c *Collector) count(keys []string) int {
	return c.counts[strings.Join(keys, ",")]
}

func (c *Collector) enumKeys() [][]string {
	var keyParts [][]string
	for i := range c.dims {
		dimKeys := slices.Sorted(maps.Keys(c.keys[i]))
		if len(keyParts) == 0 {
			for _, key := range dimKeys {
				keyParts = append(keyParts, []string{key})
			}
			continue
		}
		newKeyParts := [][]string{}
		for _, parts := range keyParts {
			for _, key := range dimKeys {
				newKeyParts = append(newKeyParts, append(parts, key))
			}
		}
		keyParts = newKeyParts
	}
	return keyParts
}

func (c *Collector) ForJSON() any {
	if len(c.counts) == 0 {
		return nil
	}

	allKeys := c.enumKeys()
	if len(allKeys) == 0 {
		return c.count([]string{})
	}

	res := make(map[string]any)
	for _, keys := range allKeys {
		v := c.count(keys)
		if v == 0 {
			continue
		}

		// Construct the map of maps.
		innerRes := res
		for _, key := range keys[:len(keys)-1] {
			if _, ok := innerRes[key]; !ok {
				innerRes[key] = make(map[string]any)
			}
			innerRes = innerRes[key].(map[string]any)
		}

		// Use the final key to store the value.
		innerRes[keys[len(keys)-1]] = v
	}
	return res
}

func (c *Collector) ForCSV() [][]string {
	res := [][]string{append(c.dims, c.name)}

	if len(c.counts) == 0 {
		// No records, so abort.
		return res
	}

	allKeys := c.enumKeys()
	if len(allKeys) == 0 {
		// The keys are all empty, but we have a value. This means that there is
		// is only a single value.
		return append(res, []string{strconv.Itoa(c.count([]string{}))})
	}

	for _, keys := range allKeys {
		v := c.count(keys)
		if v == 0 {
			continue
		}
		row := make([]string, len(c.dims)+1)
		copy(row, keys)
		row[len(row)-1] = strconv.Itoa(v)
		res = append(res, row)
	}
	return res
}
