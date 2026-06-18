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

package startkeys_test

import (
	"bytes"
	"testing"

	"github.com/ossf/malicious-packages/cmd/ingest/startkeys"
)

func TestNew(t *testing.T) {
	sk := startkeys.New()
	if sk == nil {
		t.Errorf("New() = nil; want non-nil")
	}
}

func TestGet_Empty(t *testing.T) {
	sk := startkeys.New()
	want := ""
	if got := sk.Get("dummy", "a"); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
}

func TestGet(t *testing.T) {
	sk := startkeys.New()
	sk.Set("dummy", "a", "a/key")
	want := "a/key"
	if got := sk.Get("dummy", "a"); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
}

func TestGet_Nil(t *testing.T) {
	var sk *startkeys.StartKeys
	want := ""
	if got := sk.Get("dummy", "a"); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
}

func TestSet_Nil(t *testing.T) {
	var sk *startkeys.StartKeys
	sk.Set("dummy", "a", "another/key")
	want := ""
	if got := sk.Get("dummy", "a"); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
}

func TestSet_EmptyKey(t *testing.T) {
	sk := startkeys.New()
	sk.Set("dummy", "", "and/another/key")
	sk.Set("dummy", "", "")
	want := "and/another/key"
	if got := sk.Get("dummy", ""); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
}

func TestIsDirty_Nil(t *testing.T) {
	var sk *startkeys.StartKeys
	sk.Set("dummy", "a", "path/to/key")
	want := false
	if got := sk.IsDirty(); got != want {
		t.Errorf("IsDirty() = %v; want %v", got, want)
	}
}

func TestIsDirty_New(t *testing.T) {
	sk := startkeys.New()
	want := false
	if got := sk.IsDirty(); got != want {
		t.Errorf("IsDirty() = %v; want %v", got, want)
	}
}

func TestIsDirty_Set(t *testing.T) {
	sk := startkeys.New()
	sk.Set("dummy", "a", "path/to/key")
	want := true
	if got := sk.IsDirty(); got != want {
		t.Errorf("IsDirty() = %v; want %v", got, want)
	}
}

func TestIsDirty_EmptyKey(t *testing.T) {
	sk := startkeys.New()
	sk.Set("dummy", "a", "")
	want := false
	if got := sk.IsDirty(); got != want {
		t.Errorf("IsDirty() = %v; want %v", got, want)
	}
}

func TestReadYAML_ReadOnly(t *testing.T) {
	sk := startkeys.New()
	err := sk.ReadYAML(bytes.NewBufferString(`
dummy:
  path/: path/to/key
`))
	if err != nil {
		t.Fatalf("ReadYAML() = %v; want no error", err)
	}
	want := "path/to/key"
	if got := sk.Get("dummy", "path/"); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
	if got := sk.IsDirty(); got != false {
		t.Errorf("IsDirty() = %v; want %v", got, false)
	}
}

func TestReadYAML_ThenWrite(t *testing.T) {
	sk := startkeys.New()
	err := sk.ReadYAML(bytes.NewBufferString(`
dummy:
 path/: path/to/key
`))
	if err != nil {
		t.Fatalf("ReadYAML() = %v; want no error", err)
	}
	sk.Set("dummy", "path/", "new/key")
	want := "new/key"
	if got := sk.Get("dummy", "path/"); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
	if got := sk.IsDirty(); got != true {
		t.Errorf("IsDirty() = %v; want %v", got, true)
	}
}

func TestReadYAML_ThenWriteNoChange(t *testing.T) {
	sk := startkeys.New()
	err := sk.ReadYAML(bytes.NewBufferString(`
dummy:
  path/: path/to/key
`))
	if err != nil {
		t.Fatalf("ReadYAML() = %v; want no error", err)
	}
	sk.Set("dummy", "path/", "path/to/key")
	want := "path/to/key"
	if got := sk.Get("dummy", "path/"); got != want {
		t.Errorf("Get() = %v; want %v", got, want)
	}
	if got := sk.IsDirty(); got != false {
		t.Errorf("IsDirty() = %v; want %v", got, false)
	}
}

func TestReadYAML_Error(t *testing.T) {
	sk := startkeys.New()
	err := sk.ReadYAML(bytes.NewBufferString(``))
	if err == nil {
		t.Fatal("ReadYAML() = nil; want an error")
	}
}

func TestWriteYAML(t *testing.T) {
	sk := startkeys.New()
	sk.Set("source1", "path/", "path/one")
	sk.Set("source1", "alt/", "alt/one")
	sk.Set("source2", "path/", "path/two")
	var buf bytes.Buffer
	err := sk.WriteYAML(&buf)
	if err != nil {
		t.Fatalf("WriteYAML() = %v; want no error", err)
	}
	want := "source1:\n    alt/: alt/one\n    path/: path/one\nsource2:\n    path/: path/two\n"
	if got := buf.String(); got != want {
		t.Errorf("WriteYaml wrote %#v; want %#v", got, want)
	}
}
