// Copyright 2024 Malicious Packages Authors
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

package reportfilter

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/google/osv-scanner/pkg/models"
)

var supportedFields = []string{
	"aliases",
	"related",
}

type Filter interface {
	Apply(*models.Vulnerability)
}

// New creates and returns the filter associated with the supplied arguments.
//
// An error is returned if the supplied arguments are invalid.
func New(field, pattern string) (Filter, error) {
	if !slices.Contains(supportedFields, field) {
		return nil, fmt.Errorf("unknown field: %s", field)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compiling pattern re: %w", err)
	}
	return &removeFilter{field: field, re: re}, nil
}

type removeFilter struct {
	field string
	re    *regexp.Regexp
}

func (rf *removeFilter) Apply(v *models.Vulnerability) {
	switch rf.field {
	case "aliases":
		v.Aliases = slices.DeleteFunc(v.Aliases, rf.re.MatchString)
	case "related":
		v.Related = slices.DeleteFunc(v.Related, rf.re.MatchString)
	}
}

// Filters is a slice of filters that itself implements the Filter interface.
type Filters []Filter

func (fs Filters) Apply(v *models.Vulnerability) {
	for _, f := range fs {
		f.Apply(v)
	}
}
