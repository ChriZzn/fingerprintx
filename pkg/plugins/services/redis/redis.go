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

package redis

import (
	"bytes"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

type Plugin struct{}

type Info struct {
	AuthRequired bool
}

const REDIS = "redis"

// Check if the response is from a Redis server
// returns an error if it's not validated as a Redis server
// and a Info struct with AuthRequired if it is
func checkRedis(data []byte) (Info, error) {
	// a valid pong response will be the 7 bytes [+PONG(CR)(NL)]
	pong := [7]byte{0x2b, 0x50, 0x4f, 0x4e, 0x47, 0x0d, 0x0a}
	// an auth error will start with the 7 bytes: [-NOAUTH]
	noauth := [7]byte{0x2d, 0x4e, 0x4f, 0x41, 0x55, 0x54, 0x48}

	msgLength := len(data)
	if msgLength < 7 {
		return Info{}, &shared.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "too short of a response",
		}
	}

	if msgLength == 7 {
		if bytes.Equal(data, pong[:]) {
			// Valid PONG response means redis server and no auth
			return Info{AuthRequired: false}, nil
		}
		return Info{}, &shared.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid PONG response",
		}
	}
	if !bytes.Equal(data[:7], noauth[:]) {
		return Info{}, &shared.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid Error response",
		}
	}

	return Info{AuthRequired: true}, nil
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	//https://redis.io/commands/ping/
	// PING is a supported command since 1.0.0
	// [*1(CR)(NL)$4(CR)(NL)PING(CR)(NL)]
	ping := []byte{
		0x2a,
		0x31,
		0x0d,
		0x0a,
		0x24,
		0x34,
		0x0d,
		0x0a,
		0x50,
		0x49,
		0x4e,
		0x47,
		0x0d,
		0x0a,
	}

	response, err := shared.SendRecv(conn, ping, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	result, err := checkRedis(response)
	if err != nil {
		return nil, nil
	}
	payload := ServiceRedis{
		AuthRequired: result.AuthRequired,
	}
	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return REDIS
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 413
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{6379, 16379, 6380}
}
