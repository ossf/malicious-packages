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

package source

import (
	"errors"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/ossf/malicious-packages/internal/reportfilter"
)

var (
	ErrInvalidID  = errors.New("invalid source id")
	validIDRegExp = regexp.MustCompile("[a-z0-9-]+")
)

type Filter struct {
	Field   string
	Pattern string
}

type Source struct {
	ID                string   `yaml:"id"`
	Bucket            string   `yaml:"bucket"`
	Prefixes          []string `yaml:"prefixes"`
	LookbackEntries   int      `yaml:"lookback-entries"`
	AliasID           bool     `yaml:"alias-id"`
	DisabledForReason string   `yaml:"disabled-for-reason"`
	Filters           []Filter `yaml:"filters"`

	// Internal cache populated during parsing.
	filters reportfilter.Filters
}

func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: id must be set", ErrInvalidID)
	}
	if testID := validIDRegExp.FindString(id); id != testID {
		return fmt.Errorf("%w: id must match the regex /%s/", ErrInvalidID, validIDRegExp.String())
	}
	return nil
}

func generateFilterSet(filters []Filter) (reportfilter.Filters, error) {
	fs := reportfilter.Filters{}
	for _, f := range filters {
		rf, err := reportfilter.New(f.Field, f.Pattern)
		if err != nil {
			return nil, fmt.Errorf("report filter: %w", err)
		}
		fs = append(fs, rf)
	}
	return fs, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Source) UnmarshalYAML(value *yaml.Node) error {
	type RawSource Source
	raw := &RawSource{}
	if err := value.Decode(raw); err != nil {
		return err
	}
	if err := validateID(raw.ID); err != nil {
		return err
	}
	fs, err := generateFilterSet(raw.Filters)
	if err != nil {
		return err
	}
	raw.filters = fs
	*s = Source(*raw)
	return nil
}

func (s *Source) GetPrefixes() []string {
	if len(s.Prefixes) == 0 {
		return []string{""}
	}
	return s.Prefixes
}

func (s *Source) Filter() reportfilter.Filter {
	return s.filters
}

func (s *Source) Enabled() bool {
	return s.DisabledForReason == ""
}
