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

package sourceio_test

import (
	"fmt"
	"testing"

	"github.com/ossf/malicious-packages/internal/sourceio"
)

func TestStorageType_String(t *testing.T) {
	tests := map[sourceio.StorageType]string{
		sourceio.StorageTypeNone:   "",
		sourceio.StorageTypeBlob:   "blob",
		sourceio.StorageType(9999): "unknown",
		sourceio.StorageType(-123): "unknown",
	}
	for test, want := range tests {
		t.Run(fmt.Sprintf("%d_%s", int(test), want), func(t *testing.T) {
			got := test.String()
			if got != want {
				t.Errorf("String() = %q; want %q", got, want)
			}
		})
	}
}

func TestStorageType_Identity(t *testing.T) {
	for _, want := range sourceio.AllStorageTypes {
		t.Run(want.String(), func(t *testing.T) {
			got, err := sourceio.ParseStorageType(want.String())
			if err != nil {
				t.Fatalf("ParseStorageType() = %v; want no error", err)
			}
			if got != want {
				t.Errorf("SourceType(%d) does not match SourecType(%d)", got, want)
			}
		})
	}
}
