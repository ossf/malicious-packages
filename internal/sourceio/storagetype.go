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

package sourceio

import "fmt"

type StorageType int

const (
	StorageTypeNone = StorageType(iota)
	StorageTypeBlob
	StorageTypeGit
)

var AllStorageTypes = []StorageType{
	StorageTypeNone,
	StorageTypeBlob,
	StorageTypeGit,
}

func (s StorageType) String() string {
	switch s {
	case StorageTypeNone:
		return ""
	case StorageTypeBlob:
		return "blob"
	case StorageTypeGit:
		return "git"
	default:
		return "unknown"
	}
}

func ParseStorageType(s string) (StorageType, error) {
	switch s {
	case "":
		return StorageTypeNone, nil
	case "blob":
		return StorageTypeBlob, nil
	case "git":
		return StorageTypeGit, nil
	default:
		return StorageTypeNone, fmt.Errorf("unknown storage type: %q", s)
	}
}
