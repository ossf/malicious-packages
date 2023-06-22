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
)

var (
	ErrInvalidID  = errors.New("invalid source id")
	validIDRegExp = regexp.MustCompile("[a-z0-9-]+")
)

type Source struct {
	ID              string `yaml:"id"`
	Bucket          string `yaml:"bucket"`
	Prefix          string `yaml:"prefix"`
	LookbackEntries int    `yaml:"lookback-entries"`
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
	*s = Source(*raw)
	return nil
}
