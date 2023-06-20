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

package config

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/ossf/malicious-packages/internal/source"
)

var ErrInvalidConfig = errors.New("invalid config")

type Config struct {
	IDPrefix          string           `yaml:"id-prefix"`
	MaliciousPath     string           `yaml:"malicious-path"`
	FalsePositivePath string           `yaml:"false-positive-path"`
	Sources           []*source.Source `yaml:"sources"`
}

func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	type RawConfig Config
	raw := &RawConfig{}
	if err := value.Decode(raw); err != nil {
		return err
	}
	*c = Config(*raw)
	return c.Init()
}

func (c *Config) Init() error {
	if c.IDPrefix == "" {
		return fmt.Errorf("%w: id-prefix is required", ErrInvalidConfig)
	}
	if c.MaliciousPath == "" {
		return fmt.Errorf("%w: malicious-path is required", ErrInvalidConfig)
	}
	if c.FalsePositivePath == "" {
		return fmt.Errorf("%w: false-positive-path is required", ErrInvalidConfig)
	}
	var err error
	c.MaliciousPath, err = filepath.Abs(c.MaliciousPath)
	if err != nil {
		return fmt.Errorf("invalid malicious path: %w", err)
	}
	c.FalsePositivePath, err = filepath.Abs(c.FalsePositivePath)
	if err != nil {
		return fmt.Errorf("invalid false positive path: %w", err)
	}
	if len(c.Sources) == 0 {
		return fmt.Errorf("%w: no sources specified", ErrInvalidConfig)
	}
	return nil
}

// Paths returns the config paths in a single string slice.
func (c *Config) Paths() []string {
	return []string{
		c.MaliciousPath,
		c.FalsePositivePath,
	}
}

func ReadYAML(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	var c *Config
	err := dec.Decode(&c)
	if err != nil {
		return nil, fmt.Errorf("failed decoding config yaml: %w", err)
	}
	return c, nil
}
