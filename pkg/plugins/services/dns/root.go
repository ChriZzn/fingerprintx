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

package dns

import (
	"bytes"
	"crypto/rand"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"net"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

const DNS = "dns"

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
}

func CheckDNS(conn net.Conn, timeout time.Duration) (bool, error) {
	for attempts := 0; attempts < 3; attempts++ {
		transactionID := make([]byte, 2)
		_, err := rand.Read(transactionID)
		if err != nil {
			return false, &shared.RandomizeError{Message: "Transaction ID"}
		}

		InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
			// Transaction ID
			0x01, 0x00, // Flags: 0x0100 Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, // Name: version.bind
			0x00, 0x10, // Type: TXT (Text strings) (16)
			0x00, 0x03, // Class: CH (0x0003)
		}...)

		if conn.RemoteAddr().Network() == "tcp" {
			InitialConnectionPackage = append([]byte{0x00, 0x1e}, InitialConnectionPackage...)
		}

		response, err := shared.SendRecv(conn, InitialConnectionPackage, timeout)
		if err != nil {
			return false, err
		}

		if len(response) == 0 {
			return false, nil
		}

		if conn.RemoteAddr().Network() == "udp" {
			if !bytes.Equal(transactionID[0:1], response[0:1]) {
				return false, nil
			}
		}

		if conn.RemoteAddr().Network() == "tcp" {
			if !bytes.Equal(transactionID[0:1], response[2:3]) {
				return false, nil
			}
		}
	}

	return true, nil
}
