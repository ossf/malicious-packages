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
	"fmt"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ossf/malicious-packages/internal/source"
	mppb "github.com/ossf/malicious-packages/proto"
)

const originRefKey = "malicious-packages-origins"

func (r *Report) getOrigin(sourceID, shasum string) *mppb.OriginRef {
	for _, o := range r.origins {
		if o.Source == sourceID && o.ShaSum == shasum {
			return o
		}
	}
	return nil
}

func (r *Report) HasOrigin(sourceID, shasum string) bool {
	return r.getOrigin(sourceID, shasum) != nil
}

func (r *Report) AddOrigin(sourceID, shasum string) *mppb.OriginRef {
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
	ref := &mppb.OriginRef{
		Source:       sourceID,
		ShaSum:       shasum,
		ImportTime:   timestamppb.New(time.Now().UTC()),
		ModifiedTime: timestamppb.New(modified),
		Id:           r.raw.Id,
		Ranges:       ranges,
		Versions:     versions,
	}
	r.origins = append(r.origins, ref)
	return ref
}

func (r *Report) HasCommonOrigin(other *Report) bool {
	for _, o := range r.origins {
		if other.HasOrigin(o.Source, o.ShaSum) {
			return true
		}
	}
	return false
}

func validateOrigin(o *mppb.OriginRef) error {
	if o.Source == "" {
		return fmt.Errorf("%w: missing source", ErrUnexpectedOSV)
	}

	if o.ShaSum == "" {
		return fmt.Errorf("%w: missing sha256", ErrUnexpectedOSV)
	}

	if err := source.ValidateID(o.Source); err != nil {
		return fmt.Errorf("%w: invalid source ID %q: %w", ErrUnexpectedOSV, o.Source, err)
	}
	return nil
}

func validateOrigins(os []*mppb.OriginRef) error {
	for _, o := range os {
		if err := validateOrigin(o); err != nil {
			return err
		}
	}
	return nil
}
