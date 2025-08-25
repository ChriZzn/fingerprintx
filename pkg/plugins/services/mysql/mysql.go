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

package mysql

import (
	"fmt"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

/*
When we perform fingerprinting of the MySQL service, we can expect to get one
of two packets back from the server on the initial connection. The first would
be an initial handshake packet indicating we can authenticate to the server.

The second potential response would be an error message returned by the server
telling us why we can't authenticate. For example, the server may respond with
an error message stating the client IP is not allowed to authenticate to the
server.

 Example MySQL Initial Handshake Packet:
   Length: 4a 00 00 00
   Version: 0a
   Server Version: 38 2e 30  2e 32 38 00 (null terminated string "8.0.28")
   Connection Id: 0b 00 00 00
   Auth-Plugin-Data-Part-1: 15 05 6c 51 28 32 48 15
   Filler: 00
   Capability Flags: ff ff
   Character Set: ff
   Status Flags: 02 00
   Capability Flags: ff df
   Length of Auth Plugin Data: 15
   Reserved (all 00): 00 00 00 00 00 00 00 00 00 00
   Auth-Plugin-Data-Part-2 (len 13 base 10): 26 68 15 1e 2e 7f 69 38 52 6b 6c 5c 00
   Auth Plugin Name: null terminated string "caching_sha2_password"

 Example MySQL Error Packet on Initial Connection:
   Packet Length: 45 00 00 00
   Header: ff
   Error Code: 6a 04
   Human Readable Error Message: Host '50.82.91.234' is not allowed to connect to this MySQL server
*/

type Plugin struct{}

const (
	MYSQL = "mysql"
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Run checks if the identified service is a MySQL (or MariaDB) server using
// two methods. Upon the connection of a client to a MySQL server it can return
// one of two responses. Either the server returns an initial handshake packet
// or an error message packet.
func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := shared.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	payload := ServiceMySQL{}

	if mysqlVersionStr, capabilities, err := CheckInitialHandshakePacket(response); err == nil {
		payload.PacketType = "handshake"
		payload.Version = mysqlVersionStr

		// Send SSL request packet
		sslRequest := createSSLRequest(capabilities)
		if _, err := conn.Write(sslRequest); err == nil {
			conn.Upgrade()
		}

	} else if errorStr, errorCode, err := CheckErrorMessagePacket(response); err == nil {
		payload.PacketType = "error"
		payload.ErrorMessage = errorStr
		payload.ErrorCode = errorCode
	} else {
		return nil, nil
	}
	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}

// Create MySQL SSL request packet
func createSSLRequest(serverCapabilities uint16) []byte {
	clientFlags := uint32(serverCapabilities) | 0x800 // Add SSL flag

	data := make([]byte, 32)
	pos := 0

	// Packet length (will be set later)
	pos += 4

	// Client capabilities flags
	data[pos] = byte(clientFlags)
	data[pos+1] = byte(clientFlags >> 8)
	data[pos+2] = byte(clientFlags >> 16)
	data[pos+3] = byte(clientFlags >> 24)
	pos += 4

	// Max packet size (16MB)
	data[pos] = 0x00
	data[pos+1] = 0x00
	data[pos+2] = 0x00
	data[pos+3] = 0x01
	pos += 4

	// Charset (utf8_general_ci)
	data[pos] = 0x21
	pos++

	// Reserved (23 bytes of 0)
	pos += 23

	// Set packet length
	pktLen := len(data) - 4
	data[0] = byte(pktLen)
	data[1] = byte(pktLen >> 8)
	data[2] = byte(pktLen >> 16)
	data[3] = 0x01 // Sequence number

	return data
}

func (p *Plugin) Name() string {
	return MYSQL
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 133
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{3306}
}

// CheckErrorMessagePacket checks the response packet error message
func CheckErrorMessagePacket(response []byte) (string, int, error) {
	// My brief research suggests that its not possible to get a compliant
	// error message packet that is less than eight bytes
	if len(response) < 8 {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet is too small for an error message packet",
		}
	}

	packetLength := int(
		uint32(
			response[0],
		) | uint32(
			response[1],
		)<<8 | uint32(
			response[2],
		)<<16 | uint32(
			response[3],
		)<<24,
	)
	actualResponseLength := len(response) - 4

	if packetLength != actualResponseLength {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length does not match length of the response from the server",
		}
	}

	header := int(response[4])
	if header != 0xff {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid header for an error message packet",
		}
	}

	errorCode := int(uint32(response[5]) | uint32(response[6])<<8)
	if errorCode < 1000 || errorCode > 2000 {
		return "", errorCode, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid error code",
		}
	}

	errorStr, err := readEOFTerminatedASCIIString(response, 7)
	if err != nil {
		return "", errorCode, &shared.InvalidResponseErrorInfo{Service: MYSQL, Info: err.Error()}
	}

	return errorStr, errorCode, nil
}

// CheckInitialHandshakePacket checks if the response received from the server
// matches the expected response for the MySQL service
func CheckInitialHandshakePacket(response []byte) (string, uint16, error) {
	// My brief research suggests that its not possible to get a compliant
	// initial handshake packet that is less than roughly 35 bytes
	if len(response) < 35 {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length is too small for an initial handshake packet",
		}
	}

	packetLength := int(
		uint32(
			response[0],
		) | uint32(
			response[1],
		)<<8 | uint32(
			response[2],
		)<<16 | uint32(
			response[3],
		)<<24,
	)
	version := int(response[4])

	if packetLength < 25 || packetLength > 4096 {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length doesn't make sense for the MySQL handshake packet",
		}
	}

	if version != 10 {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid version",
		}
	}

	mysqlVersionStr, position, err := readNullTerminatedASCIIString(response, 5)
	if err != nil {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "unable to read null-terminated ASCII version string, err: " + err.Error(),
		}
	}

	// If we skip the connection id and auth-plugin-data-part-1 fields the spec says
	// there is a filler byte that should always be zero at this position
	fillerPos := position + 13
	if position >= len(response) {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "buffer is too small to be a valid initial handshake packet",
		}
	}

	// According to the specification this should always be zero since it is a filler byte
	if response[fillerPos] != 0x00 {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info: fmt.Sprintf(
				"expected filler byte at ths position to be zero got: %d",
				response[fillerPos],
			),
		}
	}
	capabilities := uint16(response[fillerPos+1]) | uint16(response[fillerPos+2])<<8

	return mysqlVersionStr, capabilities, nil
}

// readNullTerminatedASCIIString is responsible for reading a null terminated
// ASCII string from a buffer and returns it as a string type
func readNullTerminatedASCIIString(buffer []byte, startPosition int) (string, int, error) {
	characters := []byte{}
	success := false
	endPosition := 0

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else if buffer[position] == 0x00 {
			success = true
			endPosition = position
			break
		} else {
			return "", 0, &shared.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	if !success {
		return "", 0, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "hit the end of the buffer without encountering a null terminator",
		}
	}

	return string(characters), endPosition, nil
}

// readEOFTerminatedASCIIString is responsible for reading an ASCII string
// that is terminated by the end of the message
func readEOFTerminatedASCIIString(buffer []byte, startPosition int) (string, error) {
	characters := []byte{}

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else {
			return "", &shared.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	return string(characters), nil
}
