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
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	mppb "github.com/ossf/malicious-packages/proto"
)

// Vuln is a test helper method that provides access to the underlying raw
// vulnerability object.
func (r *Report) Vuln() *osvschema.Vulnerability {
	return r.raw
}

// DBSpecificVuln is a test helper method that provides access to the underlying
// raw database specific vulnerability object.
func (r *Report) DBSpecificVuln() *mppb.Vulnerability {
	return r.rawDBSpecificVuln
}

// Origins is a test helper method that provides access to the underlying
// origins array.
func (r *Report) Origins() []*mppb.OriginRef {
	return r.origins
}
