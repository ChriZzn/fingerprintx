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

package postgres

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
)

type Plugin struct{}

const POSTGRES = "postgres"

// https://www.postgresql.org/docs/current/protocol-flow.html
// the following three values are the only three valid responses
// from a server for the first byte
const ErrorResponse byte = 0x45

// all of the following messages start with R (0x52)
// AuthenticationOk
// AuthenticationKerberosV5
// AuthenticationCleartextPassword
// AuthenticationMD5Password
// AuthenticationSCMCredential
// AuthenticationGSS
// AuthenticationSSPI
// AuthenticationGSSContinue
// AuthenticationSASL
// AuthenticationSASLContinue
// AuthenticationSASLFinal
// NegotiateProtocolVersion
const AuthReq byte = 0x52

const NegotiateProtocolVersionByte byte = 0x76
const ParameterStatusByte byte = 0x53

// pgMessage represents a single parsed PostgreSQL wire protocol message.
type pgMessage struct {
	Type byte
	Data []byte // message body (excludes type byte and length)
}

func verifyPSQL(data []byte) bool {
	msgLength := len(data)
	if msgLength < 6 {
		// from reading (https://www.postgresql.org/docs/14/protocol-message-formats.html)
		// no valid server response from the startup packet can be less than 6 bytes
		return false
	}

	// (heuristic) Check if length of error or authentication method is reasonable
	// (assume length is less than 16 bits)
	if data[1] != 0 || data[2] != 0 {
		return false
	}

	// ErrorResponse or NegotiateProtocolVersion status codes are probably a PSQL server
	if data[0] == ErrorResponse || data[0] == NegotiateProtocolVersionByte {
		return true
	}

	// A message starting with AuthReq is likely a PSQL server
	if data[0] == AuthReq {
		return true
	}

	// Anything else is not a valid server response
	return false
}

// buildStartupPacket constructs a PostgreSQL v3.0 startup packet from ordered key-value pairs.
// Format: Int32(length) | Int32(196608=v3.0) | key\0value\0... | \0
func buildStartupPacket(params [][2]string) []byte {
	// Calculate total length: 4 (length) + 4 (protocol version) + params + trailing null
	size := 4 + 4
	for _, kv := range params {
		size += len(kv[0]) + 1 + len(kv[1]) + 1 // key\0value\0
	}
	size++ // trailing \0

	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], uint32(size))
	binary.BigEndian.PutUint32(buf[4:8], 196608) // protocol version 3.0

	offset := 8
	for _, kv := range params {
		copy(buf[offset:], kv[0])
		offset += len(kv[0])
		buf[offset] = 0
		offset++
		copy(buf[offset:], kv[1])
		offset += len(kv[1])
		buf[offset] = 0
		offset++
	}
	buf[offset] = 0 // trailing null
	return buf
}

// parseMessages splits a PostgreSQL response buffer into individual messages.
// Each message has: type (1 byte) | Int32 length (includes self) | body.
func parseMessages(data []byte) []pgMessage {
	var msgs []pgMessage
	for len(data) >= 5 {
		msgType := data[0]
		msgLen := binary.BigEndian.Uint32(data[1:5]) // includes the 4 length bytes
		if msgLen < 4 || int(msgLen) > len(data)-1 {
			break // malformed or truncated
		}
		body := data[5 : 1+msgLen]
		msgs = append(msgs, pgMessage{Type: msgType, Data: body})
		data = data[1+msgLen:]
	}
	return msgs
}

// parseAuthMessage parses an 'R' (Authentication) message body.
// Returns the auth method name, SASL mechanisms (if applicable), and whether auth is complete (AuthOk).
func parseAuthMessage(data []byte) (method string, mechanisms []string, isAuthOk bool) {
	if len(data) < 4 {
		return "", nil, false
	}
	authType := binary.BigEndian.Uint32(data[0:4])
	switch authType {
	case 0:
		return "ok", nil, true
	case 2:
		return "kerberos", nil, false
	case 3:
		return "cleartext", nil, false
	case 5:
		return "md5", nil, false
	case 6:
		return "scm", nil, false
	case 7:
		return "gss", nil, false
	case 8:
		return "gss-continue", nil, false
	case 9:
		return "sspi", nil, false
	case 10:
		mechs := parseSASLMechanisms(data[4:])
		return "sasl", mechs, false
	case 11:
		return "sasl-continue", nil, false
	case 12:
		return "sasl-final", nil, false
	default:
		return fmt.Sprintf("unknown(%d)", authType), nil, false
	}
}

// parseSASLMechanisms reads null-terminated mechanism names from SASL auth data.
// Stops at double-null or end of data. Caps at 16 entries / 256 chars per name for safety.
func parseSASLMechanisms(data []byte) []string {
	const maxMechanisms = 16
	const maxNameLen = 256

	var mechanisms []string
	for len(data) > 0 && len(mechanisms) < maxMechanisms {
		// Find null terminator
		end := -1
		for i, b := range data {
			if b == 0 {
				end = i
				break
			}
			if i >= maxNameLen {
				return mechanisms // name too long, bail
			}
		}
		if end <= 0 {
			break // empty string (double null) or no terminator
		}
		mechanisms = append(mechanisms, string(data[:end]))
		data = data[end+1:]
	}
	return mechanisms
}

// parseErrorResponse parses an 'E' (ErrorResponse) message body.
// Extracts severity (prefers 'V' non-localized over 'S'), SQLSTATE code ('C'), and message ('M').
func parseErrorResponse(data []byte) (severity, code, message string) {
	var severityS string
	for len(data) > 0 {
		fieldType := data[0]
		data = data[1:]
		if fieldType == 0 {
			break // terminator
		}
		// Find null-terminated value
		end := -1
		for i, b := range data {
			if b == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			break // no terminator, malformed
		}
		value := string(data[:end])
		data = data[end+1:]

		switch fieldType {
		case 'S':
			severityS = value
		case 'V':
			severity = value // non-localized, preferred
		case 'C':
			code = value
		case 'M':
			message = value
		}
	}
	if severity == "" {
		severity = severityS
	}
	return severity, code, message
}

// parseNegotiateProtocolVersion parses a 'v' (NegotiateProtocolVersion) message body.
// Returns "3.<minor>" from the newest minor protocol version supported.
func parseNegotiateProtocolVersion(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	minor := binary.BigEndian.Uint32(data[0:4])
	return fmt.Sprintf("3.%d", minor)
}

// parseParameterStatus parses an 'S' (ParameterStatus) message body.
// Format: name\0value\0
func parseParameterStatus(data []byte) (name, value string) {
	// Find first null (end of name)
	nameEnd := -1
	for i, b := range data {
		if b == 0 {
			nameEnd = i
			break
		}
	}
	if nameEnd < 0 {
		return "", ""
	}
	name = string(data[:nameEnd])

	rest := data[nameEnd+1:]
	// Find second null (end of value)
	valEnd := -1
	for i, b := range rest {
		if b == 0 {
			valEnd = i
			break
		}
	}
	if valEnd < 0 {
		// No terminator — take remaining bytes
		value = string(rest)
	} else {
		value = string(rest[:valEnd])
	}
	return name, value
}

// applyParameterStatus stores recognized parameter values into the payload.
func applyParameterStatus(payload *ServicePostgreSQL, name, value string) {
	switch name {
	case "server_version":
		payload.ServerVersion = value
	case "server_encoding":
		payload.ServerEncoding = value
	case "TimeZone":
		payload.TimeZone = value
	}
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	payload := ServicePostgreSQL{}

	// Try StartTLS first before any other communication
	if conn.TLS() == nil {
		// SSL Request Packet (int32 == 80877103)
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)        // Message length
		binary.BigEndian.PutUint32(sslReq[4:8], 80877103) // SSL request code

		response, err := shared.SendRecv(conn, sslReq, timeout)
		if err == nil && len(response) > 0 {
			// 'S' indicates server supports SSL
			if response[0] == 'S' {
				payload.SSLSupported = true
				conn.Upgrade()
			}
		}
	}

	// Build startup packet programmatically (same params as the original hardcoded packet)
	startupPacket := buildStartupPacket([][2]string{
		{"user", "postgres"},
		{"database", "postgres"},
		{"application_name", "psql"},
		{"client_encoding", "UTF8"},
	})

	response, err := shared.SendRecv(conn, startupPacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	isPSQL := verifyPSQL(response)
	if !isPSQL {
		return nil, nil
	}

	// Parse all messages from the response buffer
	msgs := parseMessages(response)
	authOk := false
	for _, msg := range msgs {
		switch msg.Type {
		case AuthReq:
			method, mechs, isOk := parseAuthMessage(msg.Data)
			if method == "ok" {
				authOk = true
			} else {
				payload.AuthMethod = method
				payload.SASLMechanisms = mechs
			}
			if isOk {
				authOk = true
			}
		case ErrorResponse:
			payload.ErrorSeverity, payload.ErrorCode, payload.ErrorMessage = parseErrorResponse(msg.Data)
		case NegotiateProtocolVersionByte:
			payload.ProtocolVersion = parseNegotiateProtocolVersion(msg.Data)
		case ParameterStatusByte:
			name, value := parseParameterStatus(msg.Data)
			applyParameterStatus(&payload, name, value)
		}
	}

	payload.AuthRequired = !authOk

	// If auth succeeded (e.g. trust auth), try to read more ParameterStatus messages
	if authOk {
		extra, err := shared.Recv(conn, timeout)
		if err == nil && len(extra) > 0 {
			for _, msg := range parseMessages(extra) {
				if msg.Type == ParameterStatusByte {
					name, value := parseParameterStatus(msg.Data)
					applyParameterStatus(&payload, name, value)
				}
			}
		}
	}

	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return POSTGRES
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 1000
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{5432}
}
