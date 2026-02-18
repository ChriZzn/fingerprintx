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
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Unit Tests (no Docker) ---

func TestBuildStartupPacket(t *testing.T) {
	// The original hardcoded startup packet from the old implementation
	expected := []byte{
		0x00, 0x00, 0x00, 0x54, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x70, 0x6f, 0x73,
		0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x70,
		0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
		0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71, 0x6c, 0x00, 0x63, 0x6c,
		0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54,
		0x46, 0x38, 0x00, 0x00,
	}
	got := buildStartupPacket([][2]string{
		{"user", "postgres"},
		{"database", "postgres"},
		{"application_name", "psql"},
		{"client_encoding", "UTF8"},
	})
	assert.Equal(t, expected, got, "buildStartupPacket should match original hardcoded packet")
}

func TestBuildStartupPacketLength(t *testing.T) {
	pkt := buildStartupPacket([][2]string{{"user", "test"}})
	length := binary.BigEndian.Uint32(pkt[0:4])
	assert.Equal(t, uint32(len(pkt)), length, "length field should equal actual packet size")
	// Protocol version 3.0
	version := binary.BigEndian.Uint32(pkt[4:8])
	assert.Equal(t, uint32(196608), version)
}

func TestParseMessages(t *testing.T) {
	t.Run("single auth message", func(t *testing.T) {
		// R message: type=0x52, length=8, auth_type=5 (md5)
		msg := []byte{0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05}
		msgs := parseMessages(msg)
		require.Len(t, msgs, 1)
		assert.Equal(t, byte(0x52), msgs[0].Type)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x05}, msgs[0].Data)
	})

	t.Run("multiple messages", func(t *testing.T) {
		// Auth message (md5) + Error message
		auth := []byte{0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05}
		errBody := []byte{'S', 'F', 'A', 'T', 'A', 'L', 0, 'M', 'b', 'a', 'd', 0, 0}
		errMsg := make([]byte, 5+len(errBody))
		errMsg[0] = 0x45
		binary.BigEndian.PutUint32(errMsg[1:5], uint32(4+len(errBody)))
		copy(errMsg[5:], errBody)
		combined := append(auth, errMsg...)
		msgs := parseMessages(combined)
		require.Len(t, msgs, 2)
		assert.Equal(t, byte(0x52), msgs[0].Type)
		assert.Equal(t, byte(0x45), msgs[1].Type)
	})

	t.Run("empty data", func(t *testing.T) {
		msgs := parseMessages(nil)
		assert.Len(t, msgs, 0)
	})

	t.Run("truncated message", func(t *testing.T) {
		// Claims length of 100 but only 3 body bytes
		msg := []byte{0x52, 0x00, 0x00, 0x00, 0x64, 0x01, 0x02, 0x03}
		msgs := parseMessages(msg)
		assert.Len(t, msgs, 0, "should skip truncated messages")
	})

	t.Run("too short for header", func(t *testing.T) {
		msgs := parseMessages([]byte{0x52, 0x00, 0x00})
		assert.Len(t, msgs, 0)
	})
}

func TestParseAuthMessage(t *testing.T) {
	tests := []struct {
		name       string
		authType   uint32
		extra      []byte
		wantMethod string
		wantOk     bool
	}{
		{"auth ok", 0, nil, "ok", true},
		{"cleartext", 3, nil, "cleartext", false},
		{"md5", 5, nil, "md5", false},
		{"kerberos", 2, nil, "kerberos", false},
		{"scm", 6, nil, "scm", false},
		{"gss", 7, nil, "gss", false},
		{"sspi", 9, nil, "sspi", false},
		{"unknown type", 99, nil, "unknown(99)", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 4+len(tt.extra))
			binary.BigEndian.PutUint32(data[0:4], tt.authType)
			copy(data[4:], tt.extra)
			method, _, isOk := parseAuthMessage(data)
			assert.Equal(t, tt.wantMethod, method)
			assert.Equal(t, tt.wantOk, isOk)
		})
	}

	t.Run("sasl with mechanisms", func(t *testing.T) {
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data[0:4], 10) // SASL
		data = append(data, []byte("SCRAM-SHA-256")...)
		data = append(data, 0) // null terminator
		data = append(data, 0) // trailing null
		method, mechs, isOk := parseAuthMessage(data)
		assert.Equal(t, "sasl", method)
		assert.False(t, isOk)
		assert.Equal(t, []string{"SCRAM-SHA-256"}, mechs)
	})

	t.Run("empty data", func(t *testing.T) {
		method, _, isOk := parseAuthMessage(nil)
		assert.Equal(t, "", method)
		assert.False(t, isOk)
	})

	t.Run("short data", func(t *testing.T) {
		method, _, isOk := parseAuthMessage([]byte{0, 0})
		assert.Equal(t, "", method)
		assert.False(t, isOk)
	})
}

func TestParseSASLMechanisms(t *testing.T) {
	t.Run("single mechanism", func(t *testing.T) {
		data := append([]byte("SCRAM-SHA-256"), 0, 0)
		mechs := parseSASLMechanisms(data)
		assert.Equal(t, []string{"SCRAM-SHA-256"}, mechs)
	})

	t.Run("multiple mechanisms", func(t *testing.T) {
		var data []byte
		data = append(data, []byte("SCRAM-SHA-256")...)
		data = append(data, 0)
		data = append(data, []byte("SCRAM-SHA-256-PLUS")...)
		data = append(data, 0, 0) // trailing double null
		mechs := parseSASLMechanisms(data)
		assert.Equal(t, []string{"SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"}, mechs)
	})

	t.Run("empty data", func(t *testing.T) {
		mechs := parseSASLMechanisms(nil)
		assert.Nil(t, mechs)
	})

	t.Run("immediate null", func(t *testing.T) {
		mechs := parseSASLMechanisms([]byte{0})
		assert.Nil(t, mechs)
	})
}

func TestParseErrorResponse(t *testing.T) {
	t.Run("full error", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteByte('S')
		buf.WriteString("FATAL")
		buf.WriteByte(0)
		buf.WriteByte('V')
		buf.WriteString("FATAL")
		buf.WriteByte(0)
		buf.WriteByte('C')
		buf.WriteString("28P01")
		buf.WriteByte(0)
		buf.WriteByte('M')
		buf.WriteString("password authentication failed for user \"postgres\"")
		buf.WriteByte(0)
		buf.WriteByte(0) // terminator

		severity, code, message := parseErrorResponse(buf.Bytes())
		assert.Equal(t, "FATAL", severity)
		assert.Equal(t, "28P01", code)
		assert.Equal(t, "password authentication failed for user \"postgres\"", message)
	})

	t.Run("severity S only (no V)", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteByte('S')
		buf.WriteString("ERROR")
		buf.WriteByte(0)
		buf.WriteByte('C')
		buf.WriteString("42P01")
		buf.WriteByte(0)
		buf.WriteByte(0)

		severity, code, _ := parseErrorResponse(buf.Bytes())
		assert.Equal(t, "ERROR", severity)
		assert.Equal(t, "42P01", code)
	})

	t.Run("V preferred over S", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteByte('S')
		buf.WriteString("LOCALIZED")
		buf.WriteByte(0)
		buf.WriteByte('V')
		buf.WriteString("FATAL")
		buf.WriteByte(0)
		buf.WriteByte(0)

		severity, _, _ := parseErrorResponse(buf.Bytes())
		assert.Equal(t, "FATAL", severity, "should prefer V over S")
	})

	t.Run("empty data", func(t *testing.T) {
		severity, code, msg := parseErrorResponse(nil)
		assert.Equal(t, "", severity)
		assert.Equal(t, "", code)
		assert.Equal(t, "", msg)
	})
}

func TestParseNegotiateProtocolVersion(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := make([]byte, 8)
		binary.BigEndian.PutUint32(data[0:4], 2)
		binary.BigEndian.PutUint32(data[4:8], 0) // num unrecognized options
		result := parseNegotiateProtocolVersion(data)
		assert.Equal(t, "3.2", result)
	})

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", parseNegotiateProtocolVersion(nil))
	})

	t.Run("short data", func(t *testing.T) {
		assert.Equal(t, "", parseNegotiateProtocolVersion([]byte{0, 0}))
	})
}

func TestParseParameterStatus(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := append([]byte("server_version"), 0)
		data = append(data, []byte("15.3")...)
		data = append(data, 0)
		name, value := parseParameterStatus(data)
		assert.Equal(t, "server_version", name)
		assert.Equal(t, "15.3", value)
	})

	t.Run("no value terminator", func(t *testing.T) {
		data := append([]byte("TimeZone"), 0)
		data = append(data, []byte("UTC")...)
		name, value := parseParameterStatus(data)
		assert.Equal(t, "TimeZone", name)
		assert.Equal(t, "UTC", value)
	})

	t.Run("empty data", func(t *testing.T) {
		name, value := parseParameterStatus(nil)
		assert.Equal(t, "", name)
		assert.Equal(t, "", value)
	})

	t.Run("no null terminator", func(t *testing.T) {
		name, value := parseParameterStatus([]byte("noterm"))
		assert.Equal(t, "", name)
		assert.Equal(t, "", value)
	})
}

func TestApplyParameterStatus(t *testing.T) {
	payload := &ServicePostgreSQL{}

	applyParameterStatus(payload, "server_version", "15.3")
	assert.Equal(t, "15.3", payload.ServerVersion)

	applyParameterStatus(payload, "server_encoding", "UTF8")
	assert.Equal(t, "UTF8", payload.ServerEncoding)

	applyParameterStatus(payload, "TimeZone", "UTC")
	assert.Equal(t, "UTC", payload.TimeZone)

	applyParameterStatus(payload, "unknown_param", "value")
	// Should not panic or change anything
	assert.Equal(t, "15.3", payload.ServerVersion)
}

func TestVerifyPSQL(t *testing.T) {
	t.Run("auth message", func(t *testing.T) {
		data := []byte{0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05}
		assert.True(t, verifyPSQL(data))
	})

	t.Run("error response", func(t *testing.T) {
		data := []byte{0x45, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}
		assert.True(t, verifyPSQL(data))
	})

	t.Run("negotiate protocol version", func(t *testing.T) {
		data := []byte{0x76, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00}
		assert.True(t, verifyPSQL(data))
	})

	t.Run("too short", func(t *testing.T) {
		assert.False(t, verifyPSQL([]byte{0x52, 0x00}))
	})

	t.Run("unreasonable length", func(t *testing.T) {
		data := []byte{0x52, 0x01, 0x00, 0x00, 0x08, 0x00}
		assert.False(t, verifyPSQL(data))
	})

	t.Run("unknown type", func(t *testing.T) {
		data := []byte{0x41, 0x00, 0x00, 0x00, 0x08, 0x00}
		assert.False(t, verifyPSQL(data))
	})
}

// --- Integration Tests (Docker required) ---

func TestPostgreSQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "postgresql",
			Port:        5432,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "postgres",
				Env: []string{
					"POSTGRES_PASSWORD=secret",
					"POSTGRES_USER=user_name",
					"POSTGRES_DB=dbname",
					"listen_addresses = '*'",
				},
			},
		},
		{
			Description: "postgresql-trust-auth",
			Port:        5432,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "postgres",
				Env: []string{
					"POSTGRES_HOST_AUTH_METHOD=trust",
					"POSTGRES_USER=postgres",
					"POSTGRES_DB=postgres",
				},
			},
		},
	}

	p := &Plugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("test failed: %v", err)
			}
		})
	}
}
