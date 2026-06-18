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

package collector

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Collector is used to help collect counts across zero or more dimensions.
type Collector struct {
	name    string
	dims    []string
	dimKeys []map[string]struct{}
	counts  map[string]int
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
		c.dimKeys = append(c.dimKeys, make(map[string]struct{}))
	}
	return c
}

// Inc increments the count with each of the keys corresponding to the
// defined dimensions.
func (c *Collector) Inc(keys ...string) {
	for i, key := range keys {
		c.dimKeys[i][key] = struct{}{}
	}
	c.counts[strings.Join(keys, ",")]++
}

func (c *Collector) count(keys []string) int {
	return c.counts[strings.Join(keys, ",")]
}

func (c *Collector) sortedDimKeys() [][]string {
	dimKeys := make([][]string, len(c.dims))
	for i := range c.dims {
		keys := slices.Sorted(maps.Keys(c.dimKeys[i]))
		if len(keys) == 0 {
			// If any dimension has no keys, the cartesian product is empty.
			return nil
		}
		dimKeys[i] = keys
	}
	return dimKeys
}

func (c *Collector) ForJSON() any {
	if len(c.counts) == 0 {
		return nil
	}

	dimKeys := c.sortedDimKeys()
	if dimKeys == nil {
		return nil
	}

	var builder func([]string) any
	builder = func(keys []string) any {
		if len(keys) == len(dimKeys) {
			// We have all the dimensions, get the value.
			return c.count(keys)
		}
		// Otherwise recursively call builder to construct a map.
		keyVals := make(map[string]any)
		for _, key := range dimKeys[len(keys)] {
			val := builder(append(keys, key))
			if v, ok := val.(int); ok && v == 0 {
				// Ignore zero int values, if they are returned.
				continue
			}
			keyVals[key] = builder(append(keys, key))
		}
		return keyVals
	}
	return builder([]string{})
}

func (c *Collector) ForCSV() [][]string {
	res := [][]string{append(c.dims, c.name)}

	if len(c.counts) == 0 {
		// No records, so abort.
		return res
	}

	if len(c.dims) == 0 {
		// The keys are all empty, but we have a value. This means that there is
		// is only a single value.
		return append(res, []string{strconv.Itoa(c.count([]string{}))})
	}

	dimKeys := c.sortedDimKeys()
	if dimKeys == nil {
		return res
	}

	// Recursively build each CSV row.
	var builder func([]string)
	builder = func(keys []string) {
		if len(keys) == len(dimKeys) {
			// Stopping case: we have all the keys, so grab the value and a row.
			v := c.count(keys)
			if v != 0 {
				res = append(res, append(keys, strconv.Itoa(v)))
			}
			return
		}
		for _, key := range dimKeys[len(keys)] {
			builder(append(keys, key))
		}
	}
	builder([]string{})

	return res
}
