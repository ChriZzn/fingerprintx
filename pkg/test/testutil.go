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

package test

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

type Testcase struct {
	// Testcase description
	Description string

	// Target port for test
	Port int

	// Target protocol for test (TCP or UDP)
	Protocol plugins.Protocol

	// Function used to determine whether testcase succeeded or not
	Expected func(*plugins.Service) bool

	// Docker containers to run
	RunConfig dockertest.RunOptions
}

var dockerPool *dockertest.Pool

func RunTest(t *testing.T, tc Testcase, p plugins.Plugin) error {
	var err error
	if dockerPool == nil {
		dockerPool, err = dockertest.NewPool("")
		if err != nil {
			log.Fatalf("could not connect to docker: %s", err)
		}
		require.NoError(t, err, "could not connect to docker")
	}
	resource, err := dockerPool.RunWithOptions(&tc.RunConfig)
	require.NoError(t, err, "could not start resource")
	time.Sleep(1 * time.Second)

	// create target
	localhost, _ := netip.ParseAddr("127.0.0.1")
	port := resource.GetPort(fmt.Sprintf("%d/%s", tc.Port, tc.Protocol.String()))
	portNum, _ := strconv.ParseUint(port, 10, 16)
	testTarget := plugins.Target{
		Address:   netip.AddrPortFrom(localhost, uint16(portNum)),
		Transport: tc.Protocol,
	}

	fmt.Println("Waiting")
	//time.Sleep(600 * time.Second)

	fmt.Printf("trying to connect to: %s\n", testTarget.String())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err = dockerPool.Retry(func() error {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for container")
		default:
			time.Sleep(1 * time.Second)
			conn, dialErr := plugins.Connect(ctx, testTarget, 2*time.Second)
			if dialErr != nil {
				return dialErr
			}
			conn.Close()
			return nil
		}
	})

	defer dockerPool.Purge(resource) //nolint:errcheck
	require.NoError(t, err, "failed to connect to test container")

	fmt.Printf("opening connection: %s\n", testTarget.String())
	conn, err := plugins.Connect(context.Background(), testTarget, 3*time.Second)
	require.NoError(t, err, "failed to open connection to container")

	result, err := p.Run(conn, time.Second*3, testTarget)
	require.Equal(t, true, tc.Expected(result), "failed plugin testcase")
	require.NoError(t, err, "failed to run testcase")

	return nil
}
