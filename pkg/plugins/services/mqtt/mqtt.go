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

package mqtt

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"net"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

type Plugin struct{}

const MQTT = "mqtt5"

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func testConnectRequest(conn net.Conn, requestBytes []byte, timeout time.Duration) (bool, error) {
	response, err := shared.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &shared.ServerNotEnable{}
	}

	if response[0] == 0x20 {
		// MQTT server
		return true, nil
	}
	return true, &shared.InvalidResponseError{Service: MQTT}
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	mqttConnect5 := []byte{
		// message type 1 + 4 bits reserved
		0x10,
		// message length of 18 (the number of following bytes)
		0x12,
		// protocol name length (4)
		0x00, 0x04,
		// protocol name (MQTT)
		0x4d, 0x51, 0x54, 0x54,
		// protocol version (5)
		0x05,
		// flags (all unset except for Clean Session)
		0x02,
		// keep alive
		0x00, 0x3c,
		// properties length of 0
		0x00,
		// client ID length of 5
		0x00, 0x05,
		// client ID AAAA
		0x41, 0x41, 0x41, 0x41, 0x41,
	}

	check, err := testConnectRequest(conn, mqttConnect5, timeout)
	if check && err == nil {
		return plugins.CreateServiceFrom(target, p.Name(), ServiceMQTT{}, conn.TLS()), nil
	}
	return nil, err
}

func (p *Plugin) Priority() int {
	return 505
}

func (p *Plugin) Name() string {
	return MQTT
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{1883, 8883}
}
