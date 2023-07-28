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
	"time"

	"github.com/google/osv-scanner/pkg/models"
)

const originRefKey = "malicious-packages-origins"

type OriginRef struct {
	Source       string         `json:"source"`
	SHASum       string         `json:"sha256"`
	ImportTime   time.Time      `json:"import_time"`
	ID           string         `json:"id,omitempty"`
	ModifiedTime time.Time      `json:"modified_time"`
	Ranges       []models.Range `json:"ranges,omitempty"`
	Versions     []string       `json:"versions,omitempty"`
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
	ref := &OriginRef{
		Source:       sourceID,
		SHASum:       shasum,
		ImportTime:   time.Now().UTC(),
		ModifiedTime: r.raw.Modified.UTC(),
		ID:           r.raw.ID,
		Ranges:       r.raw.Affected[0].Ranges,
		Versions:     r.raw.Affected[0].Versions,
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
