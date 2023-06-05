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

package sourceio

import (
	"container/ring"
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	s3v2 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/service/s3"
	"gocloud.dev/blob"

	"github.com/ossf/malicious-packages/internal/source"
)

// beforeListFunc will return a function that can be passed in for the
// BeforeList field in the blob.ListOptions.
func beforeListFunc(start string) func(as func(interface{}) bool) error {
	if true || start == "" {
		return func(_ func(interface{}) bool) error { return nil }
	}
	return func(as func(interface{}) bool) error {
		var gcsQ *storage.Query
		if as(&gcsQ) {
			gcsQ.StartOffset = start
			return nil
		}
		var aws1Q *s3.ListObjectsV2Input
		if as(&aws1Q) {
			aws1Q.StartAfter = &start
			return nil
		}
		var aws1LegacyQ *s3.ListObjectsInput
		if as(&aws1LegacyQ) {
			aws1LegacyQ.Marker = &start
		}
		var aws2Q *s3v2.ListObjectsV2Input
		if as(&aws2Q) {
			aws2Q.StartAfter = &start
		}
		var aws2LegacyQ *s3v2.ListObjectsInput
		if as(&aws2LegacyQ) {
			aws2LegacyQ.Marker = &start
		}
		return nil
	}
}

// Walk iterates through the entries in the source and calls walkFn for each
// key with a reader for consuming the entry.
//
// If start is not empty, entries will be consumed from start.
func Walk(ctx context.Context, s *source.Source, start string, walkFn func(ctx context.Context, key string, r io.Reader) error) (string, error) {
	bkt, err := blob.OpenBucket(ctx, s.Bucket)
	if err != nil {
		return "", fmt.Errorf("failed opening %s: %w", s.Bucket, err)
	}
	defer bkt.Close()

	// lookback is used to determine the key that occurs s.LookbackEntries before
	// the final key. This is then returned to be used as the starting offset
	// later.
	//
	// A ring is used for tracking the lookback as it ensures we only store the
	// last s.LookbackEntries number of keys.
	//
	// A LookbackEntries value of 0 indicates that the entire source should be
	// consumed everytime. This is represented by a "nil" value for lookback.
	var lookback *ring.Ring
	if s.LookbackEntries > 0 {
		lookback = ring.New(s.LookbackEntries)
	}

	iter := bkt.List(&blob.ListOptions{
		Prefix:     s.Prefix,
		BeforeList: beforeListFunc(start),
	})
	for {
		obj, err := iter.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("listing bucket failed: %w", err)
		}
		// Ensure the key is not lexographically before the start key. Usually
		// the BeforeList option will make this always false, but for cloud
		// storage that don't support starting offsets this check will save the
		// cost of reading each object's bytes.
		if start > obj.Key {
			continue
		}
		r, err := bkt.NewReader(ctx, obj.Key, nil)
		if err != nil {
			return "", fmt.Errorf("failed to open %s: %w", obj.Key, err)
		}
		err = walkFn(ctx, obj.Key, r)
		// Call close immediately on the reader to free up the resources. Using
		// defer would cause the reader to remain open until the function returns.
		r.Close()
		if err != nil {
			return "", err
		}
		if lookback != nil {
			lookback.Value = obj.Key
			lookback = lookback.Next()
		}
	}
	end := ""
	if lookback != nil {
		// Walk the ring until we find the first non-empty string. We track the
		// number of entries to ensure we don't loop forever.
		for i := 0; end == "" && i < s.LookbackEntries; i++ {
			end, _ = lookback.Value.(string)
			lookback = lookback.Next()
		}
	}
	return end, nil
}
