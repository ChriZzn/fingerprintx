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
	"sort"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
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

// MySQL capability flags
const (
	clientSSL               uint32 = 0x00000800
	clientCompress          uint32 = 0x00000020
	clientSecureConnection  uint32 = 0x00008000
	clientPluginAuth        uint32 = 0x00080000
	clientLongPassword      uint32 = 0x00000001
	clientFoundRows         uint32 = 0x00000002
	clientLongFlag          uint32 = 0x00000004
	clientConnectWithDB     uint32 = 0x00000008
	clientNoSchema          uint32 = 0x00000010
	clientODBC              uint32 = 0x00000040
	clientLocalFiles        uint32 = 0x00000080
	clientIgnoreSpace       uint32 = 0x00000100
	clientProtocol41        uint32 = 0x00000200
	clientInteractive       uint32 = 0x00000400
	clientIgnoreSigpipe     uint32 = 0x00001000
	clientTransactions      uint32 = 0x00002000
	clientMultiStatements   uint32 = 0x00010000
	clientMultiResults      uint32 = 0x00020000
	clientPSMultiResults    uint32 = 0x00040000
	clientPluginAuthLenData uint32 = 0x00200000
	clientConnAttr          uint32 = 0x00100000
	clientSessionTrack      uint32 = 0x00800000
	clientDeprecateEOF      uint32 = 0x01000000
)

var capabilityNames = map[uint32]string{
	clientLongPassword:      "CLIENT_LONG_PASSWORD",
	clientFoundRows:         "CLIENT_FOUND_ROWS",
	clientLongFlag:          "CLIENT_LONG_FLAG",
	clientConnectWithDB:     "CLIENT_CONNECT_WITH_DB",
	clientNoSchema:          "CLIENT_NO_SCHEMA",
	clientCompress:          "CLIENT_COMPRESS",
	clientODBC:              "CLIENT_ODBC",
	clientLocalFiles:        "CLIENT_LOCAL_FILES",
	clientIgnoreSpace:       "CLIENT_IGNORE_SPACE",
	clientProtocol41:        "CLIENT_PROTOCOL_41",
	clientInteractive:       "CLIENT_INTERACTIVE",
	clientSSL:               "CLIENT_SSL",
	clientIgnoreSigpipe:     "CLIENT_IGNORE_SIGPIPE",
	clientTransactions:      "CLIENT_TRANSACTIONS",
	clientSecureConnection:  "CLIENT_SECURE_CONNECTION",
	clientMultiStatements:   "CLIENT_MULTI_STATEMENTS",
	clientMultiResults:      "CLIENT_MULTI_RESULTS",
	clientPSMultiResults:    "CLIENT_PS_MULTI_RESULTS",
	clientPluginAuth:        "CLIENT_PLUGIN_AUTH",
	clientConnAttr:          "CLIENT_CONNECT_ATTRS",
	clientPluginAuthLenData: "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
	clientSessionTrack:      "CLIENT_SESSION_TRACK",
	clientDeprecateEOF:      "CLIENT_DEPRECATE_EOF",
}

var charsetNames = map[uint8]string{
	8:   "latin1",
	33:  "utf8",
	45:  "utf8mb4",
	63:  "binary",
	224: "utf8mb4", // utf8mb4_unicode_ci
	246: "utf8mb4", // utf8mb4_general_ci (MySQL 8.0)
	255: "utf8mb4", // utf8mb4_0900_ai_ci (MySQL 8.0 default)
}

type handshakeInfo struct {
	protocolVersion int
	serverVersion   string
	serverType      string
	connectionID    uint32
	characterSet    string
	statusFlags     uint16
	capabilityFlags uint32
	capabilities    []string
	authPluginName  string
}

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

	if info, err := CheckInitialHandshakePacket(response); err == nil {
		payload.PacketType = "handshake"
		payload.Version = info.serverVersion
		payload.ServerType = info.serverType
		payload.ProtocolVersion = info.protocolVersion
		payload.ConnectionID = info.connectionID
		payload.CharacterSet = info.characterSet
		payload.StatusFlags = info.statusFlags
		payload.CapabilityFlags = info.capabilityFlags
		payload.Capabilities = info.capabilities
		payload.AuthPluginName = info.authPluginName

		// Send SSL request packet
		sslRequest := createSSLRequest(info.capabilityFlags)
		if _, err := conn.Write(sslRequest); err == nil {
			conn.Upgrade()
		}

	} else if errorStr, errorCode, sqlState, err := CheckErrorMessagePacket(response); err == nil {
		payload.PacketType = "error"
		payload.ErrorMessage = errorStr
		payload.ErrorCode = errorCode
		payload.ErrorSQLState = sqlState
	} else {
		return nil, nil
	}
	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}

// createSSLRequest creates a MySQL SSL request packet
func createSSLRequest(serverCapabilities uint32) []byte {
	clientFlags := serverCapabilities | clientSSL

	data := make([]byte, 36)
	pos := 0

	// Packet header (4 bytes: 3 length + 1 sequence)
	pos += 4

	// Client capabilities flags (4 bytes)
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

	// Set packet length (payload = total - 4 byte header)
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

// CheckErrorMessagePacket checks the response packet error message.
// Returns the error string, error code, SQL state (may be empty), and any parsing error.
func CheckErrorMessagePacket(response []byte) (string, int, string, error) {
	// My brief research suggests that its not possible to get a compliant
	// error message packet that is less than eight bytes
	if len(response) < 8 {
		return "", 0, "", &shared.InvalidResponseErrorInfo{
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
		return "", 0, "", &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length does not match length of the response from the server",
		}
	}

	header := int(response[4])
	if header != 0xff {
		return "", 0, "", &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid header for an error message packet",
		}
	}

	errorCode := int(uint32(response[5]) | uint32(response[6])<<8)
	if errorCode < 1000 || errorCode > 2000 {
		return "", errorCode, "", &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid error code",
		}
	}

	// Check for SQL state marker '#' at position 7
	// Format: ff [error_code 2] '#' [SQL state 5] [message...]
	if len(response) > 13 && response[7] == '#' {
		sqlState := string(response[8:13])
		errorStr, err := readEOFTerminatedASCIIString(response, 13)
		if err != nil {
			return "", errorCode, sqlState, &shared.InvalidResponseErrorInfo{Service: MYSQL, Info: err.Error()}
		}
		return errorStr, errorCode, sqlState, nil
	}

	// No SQL state marker — message starts at byte 7
	errorStr, err := readEOFTerminatedASCIIString(response, 7)
	if err != nil {
		return "", errorCode, "", &shared.InvalidResponseErrorInfo{Service: MYSQL, Info: err.Error()}
	}

	return errorStr, errorCode, "", nil
}

// CheckInitialHandshakePacket checks if the response received from the server
// matches the expected response for the MySQL service and extracts handshake details.
func CheckInitialHandshakePacket(response []byte) (*handshakeInfo, error) {
	// My brief research suggests that its not possible to get a compliant
	// initial handshake packet that is less than roughly 35 bytes
	if len(response) < 35 {
		return nil, &shared.InvalidResponseErrorInfo{
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
		return nil, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length doesn't make sense for the MySQL handshake packet",
		}
	}

	if version != 10 {
		return nil, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid version",
		}
	}

	mysqlVersionStr, position, err := readNullTerminatedASCIIString(response, 5)
	if err != nil {
		return nil, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "unable to read null-terminated ASCII version string, err: " + err.Error(),
		}
	}

	info := &handshakeInfo{
		protocolVersion: version,
		serverVersion:   mysqlVersionStr,
	}

	// Connection ID: 4 bytes after the null-terminated version string
	connIDPos := position + 1
	if connIDPos+4 > len(response) {
		return nil, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "buffer is too small to read connection ID",
		}
	}
	info.connectionID = uint32(response[connIDPos]) |
		uint32(response[connIDPos+1])<<8 |
		uint32(response[connIDPos+2])<<16 |
		uint32(response[connIDPos+3])<<24

	// Skip auth-plugin-data-part-1 (8 bytes) after connection ID
	fillerPos := connIDPos + 4 + 8
	if fillerPos >= len(response) {
		return nil, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "buffer is too small to be a valid initial handshake packet",
		}
	}

	// According to the specification this should always be zero since it is a filler byte
	if response[fillerPos] != 0x00 {
		return nil, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info: fmt.Sprintf(
				"expected filler byte at ths position to be zero got: %d",
				response[fillerPos],
			),
		}
	}

	// Lower capability flags (2 bytes)
	capLowPos := fillerPos + 1
	if capLowPos+2 > len(response) {
		return nil, &shared.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "buffer is too small to read capability flags",
		}
	}
	capLow := uint16(response[capLowPos]) | uint16(response[capLowPos+1])<<8
	info.capabilityFlags = uint32(capLow)

	// Character set (1 byte) — optional from here
	charsetPos := capLowPos + 2
	if charsetPos >= len(response) {
		info.serverType, info.serverVersion = detectServerType(mysqlVersionStr)
		info.capabilities = decodeCapabilities(info.capabilityFlags)
		return info, nil
	}
	charsetByte := response[charsetPos]
	if name, ok := charsetNames[charsetByte]; ok {
		info.characterSet = name
	} else {
		info.characterSet = fmt.Sprintf("unknown(%d)", charsetByte)
	}

	// Status flags (2 bytes)
	statusPos := charsetPos + 1
	if statusPos+2 > len(response) {
		info.serverType, info.serverVersion = detectServerType(mysqlVersionStr)
		info.capabilities = decodeCapabilities(info.capabilityFlags)
		return info, nil
	}
	info.statusFlags = uint16(response[statusPos]) | uint16(response[statusPos+1])<<8

	// Upper capability flags (2 bytes)
	capHighPos := statusPos + 2
	if capHighPos+2 > len(response) {
		info.serverType, info.serverVersion = detectServerType(mysqlVersionStr)
		info.capabilities = decodeCapabilities(info.capabilityFlags)
		return info, nil
	}
	capHigh := uint16(response[capHighPos]) | uint16(response[capHighPos+1])<<8
	info.capabilityFlags = uint32(capLow) | uint32(capHigh)<<16

	// Auth data length (1 byte)
	authLenPos := capHighPos + 2
	if authLenPos >= len(response) {
		info.serverType, info.serverVersion = detectServerType(mysqlVersionStr)
		info.capabilities = decodeCapabilities(info.capabilityFlags)
		return info, nil
	}
	authDataLen := int(response[authLenPos])

	// Skip reserved 10 bytes
	reservedPos := authLenPos + 1
	if reservedPos+10 > len(response) {
		info.serverType, info.serverVersion = detectServerType(mysqlVersionStr)
		info.capabilities = decodeCapabilities(info.capabilityFlags)
		return info, nil
	}

	// Auth-plugin-data-part-2: max(13, authDataLen - 8) bytes
	authData2Pos := reservedPos + 10
	authData2Len := authDataLen - 8
	if authData2Len < 13 {
		authData2Len = 13
	}

	// Auth plugin name (null-terminated string after auth-plugin-data-part-2)
	authPluginPos := authData2Pos + authData2Len
	if authPluginPos < len(response) {
		if pluginName, _, err := readNullTerminatedASCIIString(response, authPluginPos); err == nil {
			info.authPluginName = pluginName
		}
	}

	info.serverType, info.serverVersion = detectServerType(mysqlVersionStr)
	info.capabilities = decodeCapabilities(info.capabilityFlags)

	return info, nil
}

// detectServerType determines if the server is MySQL or MariaDB from the version string.
// MariaDB servers often report versions like "5.5.5-10.6.4-MariaDB".
func detectServerType(version string) (serverType string, cleanVersion string) {
	if strings.Contains(version, "MariaDB") {
		// Strip the "5.5.5-" prefix that MariaDB adds for compatibility
		clean := version
		if strings.HasPrefix(clean, "5.5.5-") {
			clean = clean[6:]
		}
		return "MariaDB", clean
	}
	return "MySQL", version
}

// decodeCapabilities returns a sorted list of human-readable capability flag names.
func decodeCapabilities(flags uint32) []string {
	var names []string
	for flag, name := range capabilityNames {
		if flags&flag != 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
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
