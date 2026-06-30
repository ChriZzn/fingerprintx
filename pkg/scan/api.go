// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scan

import (
	"context"
	"log"
	"sync"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

// Scan fingerprints service(s) running given a list of targets. (Entrypoint)
//
// Targets are scanned across config.Concurrency parallel workers. A value <= 1
// scans sequentially (the default) and reproduces the original behavior exactly:
// results are returned in input-target order, and a cancelled context yields the
// partial results gathered so far together with ctx.Err(). Each target is still
// fingerprinted in full by a single worker; concurrency only parallelizes across
// distinct targets.
func Scan(targets []plugins.Target, config Config) ([]plugins.Service, error) {

	if config.Ctx == nil {
		config.Ctx = context.Background()
	}

	if len(targets) == 0 {
		return nil, nil
	}

	// Honor a context that was already cancelled before any work starts, matching
	// the sequential loop's pre-iteration check on the first target.
	select {
	case <-config.Ctx.Done():
		return nil, config.Ctx.Err()
	default:
	}

	concurrency := config.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	// results is index-aligned with targets: each slot is written by exactly one
	// worker and every read happens after wg.Wait(), so no locking is needed.
	results := make([]*plugins.Service, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				scanOne(&config, targets, results, idx)
			}
		}()
	}

	// Dispatch target indices to the workers. Stop early if the context is
	// cancelled; fedAll records whether every target was dispatched.
	fedAll := true
feed:
	for i := range targets {
		select {
		case <-config.Ctx.Done():
			fedAll = false
			break feed
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	var out []plugins.Service
	for _, r := range results {
		if r != nil {
			out = append(out, *r)
		}
	}

	// Mirror the sequential contract: only surface ctx.Err() when cancellation
	// stopped us before dispatching every target.
	if !fedAll {
		return out, config.Ctx.Err()
	}
	return out, nil
}

// scanOne fingerprints a single target and stores any result in its index slot.
// It isolates panics so a misbehaving plugin can never crash a worker goroutine
// (which would take down the whole process); a skipped target leaves its slot nil.
func scanOne(config *Config, targets []plugins.Target, results []*plugins.Service, idx int) {
	target := targets[idx]

	defer func() {
		if r := recover(); r != nil && config.Verbose {
			log.Printf("panic scanning %v: %v\n", target.Address.String(), r)
		}
	}()

	// Skip work promptly if the scan was cancelled while this job was queued.
	select {
	case <-config.Ctx.Done():
		return
	default:
	}

	result, err := config.RunTargetScan(target)
	if err == nil && result != nil {
		results[idx] = result
	}
	if config.Verbose && err != nil {
		log.Printf("%s\n", err)
	}
}
