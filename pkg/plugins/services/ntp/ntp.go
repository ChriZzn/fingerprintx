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

package ntp

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

const NTP = "ntp"

type Plugin struct{}

var ModeServer uint8 = 4

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func parseNTPResponse(response []byte) ServiceNTP {
	// First byte contains LI (2 bits), VN (3 bits), and Mode (3 bits)
	leap := (response[0] >> 6) & 0x03    // Get first 2 bits
	version := (response[0] >> 3) & 0x07 // Get next 3 bits
	stratum := response[1]
	poll := response[2]
	precision := int8(response[3])

	// Root delay is a 32-bit fixed-point number in NTP short format
	// First 16 bits are seconds, last 16 bits are fraction
	rootDelay := float64(uint32(response[4])<<24|uint32(response[5])<<16|
		uint32(response[6])<<8|uint32(response[7])) / 65536.0

	// Root dispersion is also a 32-bit fixed-point number
	rootDispersion := float64(uint32(response[8])<<24|uint32(response[9])<<16|
		uint32(response[10])<<8|uint32(response[11])) / 65536.0

	// Reference ID is a 32-bit integer
	refID := uint32(response[12])<<24 | uint32(response[13])<<16 |
		uint32(response[14])<<8 | uint32(response[15])

	// Reference timestamp is a 64-bit NTP timestamp
	refTime := float64(uint64(response[16])<<56|uint64(response[17])<<48|
		uint64(response[18])<<40|uint64(response[19])<<32|
		uint64(response[20])<<24|uint64(response[21])<<16|
		uint64(response[22])<<8|uint64(response[23])) / (1 << 32)

	return ServiceNTP{
		ProtocolVersion: version,
		Stratum:         stratum,
		Leap:            leap,
		Precision:       precision,
		RootDelay:       rootDelay,
		RootDispersion:  rootDispersion,
		RefID:           refID,
		RefTime:         refTime,
		Poll:            poll,
	}
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// reference: https://datatracker.ietf.org/doc/html/rfc5905#section-7.3
	InitialConnectionPackage := []byte{
		0xe3, 0x00, 0x0a, 0xf8, // LI/VN/Mode | Stratum | Poll | Precision
		0x00, 0x00, 0x00, 0x00, // Root Delay
		0x00, 0x00, 0x00, 0x00, // Root Dispersion
		0x00, 0x00, 0x00, 0x00, // Reference Identifier
		0x00, 0x00, 0x00, 0x00, // Reference Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Origin Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Receive Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Transmit Timestamp
		0x00, 0x00, 0x00, 0x00,
	}

	response, err := shared.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// check if response is valid NTP packet
	if response[0]&0x07 == ModeServer && len(response) == len(InitialConnectionPackage) {
		ntpService := parseNTPResponse(response)
		return plugins.CreateServiceFrom(target, p.Name(), ntpService, conn.TLS()), nil
	}
	return nil, nil

}

func (p *Plugin) Name() string {
	return NTP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 800
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{123}
}
