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
	"encoding/json"
	"testing"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedis(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "redis",
			Port:        6379,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "redis",
			},
		},
		{
			Description: "redis-with-auth",
			Port:        6379,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				if res == nil {
					return false
				}
				var metadata ServiceRedis
				if err := json.Unmarshal(res.Metadata, &metadata); err != nil {
					return false
				}
				return metadata.AuthRequired
			},
			RunConfig: dockertest.RunOptions{
				Repository: "redis",
				Cmd:        []string{"redis-server", "--requirepass", "testpass123"},
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

func TestBuildRESPCommand(t *testing.T) {
	t.Run("PING matches original hardcoded bytes", func(t *testing.T) {
		// Original hardcoded PING: *1\r\n$4\r\nPING\r\n
		original := []byte{
			0x2a, 0x31, 0x0d, 0x0a,
			0x24, 0x34, 0x0d, 0x0a,
			0x50, 0x49, 0x4e, 0x47,
			0x0d, 0x0a,
		}
		assert.Equal(t, original, buildRESPCommand("PING"))
	})

	t.Run("multi-arg command", func(t *testing.T) {
		result := buildRESPCommand("INFO", "server")
		expected := []byte("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
		assert.Equal(t, expected, result)
	})

	t.Run("single empty arg", func(t *testing.T) {
		result := buildRESPCommand("")
		expected := []byte("*1\r\n$0\r\n\r\n")
		assert.Equal(t, expected, result)
	})
}

func TestParseBulkString(t *testing.T) {
	t.Run("valid bulk string", func(t *testing.T) {
		data := []byte("$5\r\nhello\r\n")
		assert.Equal(t, []byte("hello"), parseBulkString(data))
	})

	t.Run("empty bulk string", func(t *testing.T) {
		data := []byte("$0\r\n\r\n")
		assert.Equal(t, []byte(""), parseBulkString(data))
	})

	t.Run("negative length", func(t *testing.T) {
		data := []byte("$-1\r\n")
		assert.Nil(t, parseBulkString(data))
	})

	t.Run("truncated body", func(t *testing.T) {
		data := []byte("$100\r\nshort\r\n")
		assert.Nil(t, parseBulkString(data))
	})

	t.Run("missing CRLF after length", func(t *testing.T) {
		data := []byte("$5hello")
		assert.Nil(t, parseBulkString(data))
	})

	t.Run("not a bulk string", func(t *testing.T) {
		data := []byte("+OK\r\n")
		assert.Nil(t, parseBulkString(data))
	})

	t.Run("empty input", func(t *testing.T) {
		assert.Nil(t, parseBulkString([]byte{}))
	})
}

func TestParseInfoSection(t *testing.T) {
	t.Run("realistic INFO server output", func(t *testing.T) {
		data := []byte("# Server\r\n" +
			"redis_version:7.2.4\r\n" +
			"redis_mode:standalone\r\n" +
			"os:Linux 5.15.0-1053-azure x86_64\r\n" +
			"tcp_port:6379\r\n" +
			"\r\n" +
			"# Clients\r\n" +
			"connected_clients:1\r\n")
		result := parseInfoSection(data)
		assert.Equal(t, "7.2.4", result["redis_version"])
		assert.Equal(t, "standalone", result["redis_mode"])
		assert.Equal(t, "Linux 5.15.0-1053-azure x86_64", result["os"])
		assert.Equal(t, "6379", result["tcp_port"])
		assert.Equal(t, "1", result["connected_clients"])
	})

	t.Run("empty input", func(t *testing.T) {
		result := parseInfoSection([]byte{})
		assert.Empty(t, result)
	})

	t.Run("only headers and blanks", func(t *testing.T) {
		data := []byte("# Server\r\n\r\n# Clients\r\n")
		result := parseInfoSection(data)
		assert.Empty(t, result)
	})

	t.Run("malformed lines are skipped", func(t *testing.T) {
		data := []byte("good_key:good_value\r\nno_colon_here\r\nbad\r\n")
		result := parseInfoSection(data)
		assert.Equal(t, "good_value", result["good_key"])
		assert.Len(t, result, 1)
	})

	t.Run("value containing colons", func(t *testing.T) {
		data := []byte("executable:/usr/bin/redis-server\r\n")
		result := parseInfoSection(data)
		assert.Equal(t, "/usr/bin/redis-server", result["executable"])
	})
}

func TestParseRESPError(t *testing.T) {
	t.Run("NOAUTH error", func(t *testing.T) {
		data := []byte("-NOAUTH Authentication required.\r\n")
		errType, msg := parseRESPError(data)
		assert.Equal(t, "NOAUTH", errType)
		assert.Equal(t, "NOAUTH Authentication required.", msg)
	})

	t.Run("DENIED error", func(t *testing.T) {
		data := []byte("-DENIED Redis is running in protected mode.\r\n")
		errType, msg := parseRESPError(data)
		assert.Equal(t, "DENIED", errType)
		assert.Equal(t, "DENIED Redis is running in protected mode.", msg)
	})

	t.Run("single word error", func(t *testing.T) {
		data := []byte("-ERR\r\n")
		errType, msg := parseRESPError(data)
		assert.Equal(t, "ERR", errType)
		assert.Equal(t, "ERR", msg)
	})

	t.Run("empty data", func(t *testing.T) {
		errType, msg := parseRESPError([]byte{})
		assert.Equal(t, "", errType)
		assert.Equal(t, "", msg)
	})

	t.Run("not an error", func(t *testing.T) {
		errType, msg := parseRESPError([]byte("+OK\r\n"))
		assert.Equal(t, "", errType)
		assert.Equal(t, "", msg)
	})
}

func TestCheckRedis(t *testing.T) {
	t.Run("PONG response", func(t *testing.T) {
		result, err := checkRedis([]byte("+PONG\r\n"))
		require.NoError(t, err)
		assert.False(t, result.AuthRequired)
		assert.False(t, result.ProtectedMode)
		assert.Empty(t, result.ErrorMessage)
	})

	t.Run("NOAUTH response", func(t *testing.T) {
		result, err := checkRedis([]byte("-NOAUTH Authentication required.\r\n"))
		require.NoError(t, err)
		assert.True(t, result.AuthRequired)
		assert.False(t, result.ProtectedMode)
		assert.Equal(t, "NOAUTH Authentication required.", result.ErrorMessage)
	})

	t.Run("DENIED response", func(t *testing.T) {
		result, err := checkRedis([]byte("-DENIED Redis is running in protected mode.\r\n"))
		require.NoError(t, err)
		assert.True(t, result.AuthRequired)
		assert.True(t, result.ProtectedMode)
		assert.Contains(t, result.ErrorMessage, "DENIED")
	})

	t.Run("too short", func(t *testing.T) {
		_, err := checkRedis([]byte("hi"))
		assert.Error(t, err)
	})

	t.Run("unknown response", func(t *testing.T) {
		_, err := checkRedis([]byte("+SOMETHING\r\n"))
		assert.Error(t, err)
	})

	t.Run("unknown error type", func(t *testing.T) {
		_, err := checkRedis([]byte("-ERR unknown command\r\n"))
		assert.Error(t, err)
	})
}
