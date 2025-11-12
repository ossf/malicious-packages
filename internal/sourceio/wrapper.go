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

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type StorageWrapper struct {
	Storage
}

func Wrap(s Storage) StorageWrapper {
	return StorageWrapper{
		Storage: s,
	}
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *StorageWrapper) UnmarshalYAML(value *yaml.Node) error {
	type typeStruct struct {
		Type string `yaml:"type"`
	}
	t := &typeStruct{}
	if err := value.Decode(t); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidStorage, err)
	}
	st, err := ParseStorageType(t.Type)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidStorage, err)
	}

	storage, err := unmarshalStorageYAML(st, value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidStorage, err)
	}

	s.Storage = storage
	return nil
}

func unmarshalStorageYAML(st StorageType, value *yaml.Node) (Storage, error) {
	switch st {
	case StorageTypeNone:
		return nil, nil
	case StorageTypeBlob:
		var b BlobStorage
		if err := value.Decode(&b); err != nil {
			return nil, err
		}
		return &b, nil
	case StorageTypeGit:
		g := GitStorage{
			Branch: defaultGitBranch,
		}
		if err := value.Decode(&g); err != nil {
			return nil, err
		}
		return &g, nil
	default:
		// Other checks should make this code unreachable.
		return nil, fmt.Errorf("unsupported storage type %q", st.String())
	}
}
