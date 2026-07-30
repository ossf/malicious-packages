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

package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/ossf/malicious-packages/internal/source"
)

// RangeSlice is convenience type for correctly marshaling instances of the
// osvschema.Range proto embedded in the Origin struct that is not a proto.
// Use a type over the slice is much easier than having a type for Range.
type RangeSlice []*osvschema.Range

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *RangeSlice) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var ranges []*osvschema.Range
	for i, r := range raw {
		var newRange osvschema.Range
		if err := protojson.Unmarshal(r, &newRange); err != nil {
			return fmt.Errorf("failed unmarshaling range %d: %w", i, err)
		}
		ranges = append(ranges, &newRange)
	}
	*s = ranges
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (s RangeSlice) MarshalJSON() ([]byte, error) {
	var raw []json.RawMessage
	for i, r := range s {
		b, err := protojson.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("failed marshaling range %d: %w", i, err)
		}
		raw = append(raw, b)
	}
	return json.Marshal(raw)
}

const originRefKey = "malicious-packages-origins"

type OriginRef struct {
	Source       string     `json:"source"`
	SHASum       string     `json:"sha256"`
	ImportTime   time.Time  `json:"import_time"`
	ID           string     `json:"id,omitempty"`
	ModifiedTime time.Time  `json:"modified_time"`
	Ranges       RangeSlice `json:"ranges,omitempty"`
	Versions     []string   `json:"versions,omitempty"`
}

// UnmarshalJSON implements the json.Unmarshaler interface.
//
// The implementation ensures that the resulting parsed data is valid for the
// purposes of tracking malicious packages.
func (o *OriginRef) UnmarshalJSON(b []byte) error {
	type raw OriginRef
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}

	if r.Source == "" {
		return fmt.Errorf("%w: missing source", ErrUnexpectedOSV)
	}

	if r.SHASum == "" {
		return fmt.Errorf("%w: missing sha256", ErrUnexpectedOSV)
	}

	if err := source.ValidateID(r.Source); err != nil {
		return fmt.Errorf("%w: invalid source ID %q: %w", ErrUnexpectedOSV, r.Source, err)
	}

	*o = OriginRef(r)
	return nil
}

func (r *Report) getOrigin(sourceID, shasum string) *OriginRef {
	for _, o := range r.origins {
		if o.Source == sourceID && o.SHASum == shasum {
			return o
		}
	}
	return nil
}

func (r *Report) HasOrigin(sourceID, shasum string) bool {
	return r.getOrigin(sourceID, shasum) != nil
}

func (r *Report) AddOrigin(sourceID, shasum string) *OriginRef {
	var modified time.Time
	if r.raw.Modified != nil && r.raw.Modified.IsValid() {
		modified = r.raw.Modified.AsTime().UTC()
	}
	var ranges []*osvschema.Range
	var versions []string
	if len(r.raw.Affected) > 0 {
		ranges = r.raw.Affected[0].Ranges
		versions = r.raw.Affected[0].Versions
	}
	ref := &OriginRef{
		Source:       sourceID,
		SHASum:       shasum,
		ImportTime:   time.Now().UTC(),
		ModifiedTime: modified,
		ID:           r.raw.Id,
		Ranges:       ranges,
		Versions:     versions,
	}
	r.origins = append(r.origins, ref)
	return ref
}

func (r *Report) HasCommonOrigin(other *Report) bool {
	for _, o := range r.origins {
		if other.HasOrigin(o.Source, o.SHASum) {
			return true
		}
	}
	return false
}
