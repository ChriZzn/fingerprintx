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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
)

type Plugin struct{}

const REDIS = "redis"

type pingResult struct {
	AuthRequired  bool
	ProtectedMode bool
	ErrorMessage  string
}

// buildRESPCommand encodes a Redis command as a RESP array of bulk strings.
// e.g. buildRESPCommand("PING") => "*1\r\n$4\r\nPING\r\n"
func buildRESPCommand(args ...string) []byte {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("*%d\r\n", len(args)))
	for _, arg := range args {
		buf.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg))
	}
	return buf.Bytes()
}

// parseBulkString parses a RESP bulk string response: $<len>\r\n<body>\r\n
// Returns the body bytes, or nil if the response is not a valid bulk string.
func parseBulkString(data []byte) []byte {
	if len(data) < 4 || data[0] != '$' {
		return nil
	}

	crlfIdx := bytes.Index(data, []byte("\r\n"))
	if crlfIdx < 0 {
		return nil
	}

	length, err := strconv.Atoi(string(data[1:crlfIdx]))
	if err != nil || length < 0 {
		return nil
	}

	bodyStart := crlfIdx + 2
	bodyEnd := bodyStart + length
	if bodyEnd > len(data) {
		return nil
	}

	return data[bodyStart:bodyEnd]
}

// parseInfoSection parses a Redis INFO response into key-value pairs.
// Lines starting with # are headers and are skipped, as are blank lines.
func parseInfoSection(data []byte) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		result[key] = value
	}
	return result
}

// parseRESPError parses a RESP error response: -ERRTYPE message\r\n
// Returns the error type (e.g. "NOAUTH") and the full message text.
func parseRESPError(data []byte) (errType, message string) {
	if len(data) < 2 || data[0] != '-' {
		return "", ""
	}

	// Strip leading '-' and trailing \r\n
	line := string(data[1:])
	if idx := strings.Index(line, "\r\n"); idx >= 0 {
		line = line[:idx]
	}

	errType, message, ok := strings.Cut(line, " ")
	if !ok {
		return line, line
	}
	return errType, errType + " " + message
}

// checkRedis validates a PING response from a Redis server.
// Returns a pingResult describing the server state, or an error if the
// response does not look like Redis at all.
func checkRedis(data []byte) (pingResult, error) {
	if len(data) < 5 {
		return pingResult{}, &shared.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "too short of a response",
		}
	}

	// +PONG\r\n — no auth required
	if bytes.Equal(data, []byte("+PONG\r\n")) {
		return pingResult{}, nil
	}

	// Error responses start with '-'
	if data[0] == '-' {
		errType, msg := parseRESPError(data)
		switch errType {
		case "NOAUTH":
			return pingResult{
				AuthRequired: true,
				ErrorMessage: msg,
			}, nil
		case "DENIED":
			return pingResult{
				AuthRequired:  true,
				ProtectedMode: true,
				ErrorMessage:  msg,
			}, nil
		}
	}

	return pingResult{}, &shared.InvalidResponseErrorInfo{
		Service: REDIS,
		Info:    "unrecognized response",
	}
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := shared.SendRecv(conn, buildRESPCommand("PING"), timeout)
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
		AuthRequired:  result.AuthRequired,
		ProtectedMode: result.ProtectedMode,
		ErrorMessage:  result.ErrorMessage,
	}

	// If no auth is required, try to enrich with INFO server data.
	if !result.AuthRequired {
		infoResp, err := shared.SendRecv(conn, buildRESPCommand("INFO", "server"), timeout)
		if err == nil && len(infoResp) > 0 {
			if body := parseBulkString(infoResp); body != nil {
				info := parseInfoSection(body)
				payload.Version = info["redis_version"]
				payload.RedisMode = info["redis_mode"]
				payload.OS = info["os"]
			}
		}
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
