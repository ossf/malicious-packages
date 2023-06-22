// Copyright 2022 Malicious Packages Authors
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

import "github.com/google/osv-scanner/pkg/models"

// Vuln is a test helper method that provides access to the underlying raw
// vulnerability object.
func (r *Report) Vuln() *models.Vulnerability {
	return r.raw
}

// Origins is a test helper method that provides access to the underlying
// origins array.
func (r *Report) Origins() []*OriginRef {
	return r.origins
}
