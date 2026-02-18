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

package ssh

import (
	"encoding/json"
	"testing"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSH(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "ssh",
			Port:        22,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				if res == nil {
					return false
				}
				raw, err := json.Marshal(res.Metadata)
				if err != nil {
					return false
				}
				var meta ServiceSSH
				if err := json.Unmarshal(raw, &meta); err != nil {
					return false
				}
				if meta.ProtocolVersion == "" || meta.SoftwareVersion == "" {
					return false
				}
				if meta.Algorithms == nil || len(meta.Algorithms.KexAlgorithms) == 0 {
					return false
				}
				return true
			},
			RunConfig: dockertest.RunOptions{
				Repository: "sickp/alpine-sshd",
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

func TestParseBanner(t *testing.T) {
	tests := []struct {
		name     string
		banner   string
		proto    string
		software string
		comments string
	}{
		{
			name:     "OpenSSH with comments",
			banner:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
			proto:    "2.0",
			software: "OpenSSH_8.9p1",
			comments: "Ubuntu-3ubuntu0.6",
		},
		{
			name:     "OpenSSH without comments",
			banner:   "SSH-2.0-OpenSSH_9.0\r\n",
			proto:    "2.0",
			software: "OpenSSH_9.0",
			comments: "",
		},
		{
			name:     "older protocol version",
			banner:   "SSH-1.99-OpenSSH_3.9p1",
			proto:    "1.99",
			software: "OpenSSH_3.9p1",
			comments: "",
		},
		{
			name:     "non-SSH input",
			banner:   "HTTP/1.1 200 OK\r\n",
			proto:    "",
			software: "",
			comments: "",
		},
		{
			name:     "dropbear",
			banner:   "SSH-2.0-dropbear_2022.83\r\n",
			proto:    "2.0",
			software: "dropbear_2022.83",
			comments: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto, software, comments := parseBanner(tt.banner)
			assert.Equal(t, tt.proto, proto)
			assert.Equal(t, tt.software, software)
			assert.Equal(t, tt.comments, comments)
		})
	}
}

func TestParseAttemptedMethods(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected []string
	}{
		{
			name:     "all three methods",
			errMsg:   "ssh: handshake failed: ssh: unable to authenticate, attempted methods [publickey password keyboard-interactive], no supported methods remain",
			expected: []string{"publickey", "password", "keyboard-interactive"},
		},
		{
			name:     "single method",
			errMsg:   "ssh: unable to authenticate, attempted methods [publickey], no supported methods remain",
			expected: []string{"publickey"},
		},
		{
			name:     "empty list",
			errMsg:   "ssh: unable to authenticate, attempted methods [], no supported methods remain",
			expected: nil,
		},
		{
			name:     "unrelated error",
			errMsg:   "dial tcp 127.0.0.1:22: connection refused",
			expected: nil,
		},
		{
			name:     "no closing bracket",
			errMsg:   "ssh: unable to authenticate, attempted methods [publickey password",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAttemptedMethods(tt.errMsg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAlgoMapToStruct(t *testing.T) {
	t.Run("converts map to struct", func(t *testing.T) {
		input := map[string]string{
			"KexAlgos":                "curve25519-sha256,diffie-hellman-group14-sha256",
			"ServerHostKeyAlgos":      "ssh-ed25519,rsa-sha2-512",
			"CiphersClientServer":     "aes128-ctr,aes256-ctr",
			"CiphersServerClient":     "aes128-ctr,aes256-ctr",
			"MACsClientServer":        "hmac-sha2-256",
			"MACsServerClient":        "hmac-sha2-256",
			"CompressionClientServer": "none",
			"CompressionServerClient": "none",
			"Cookie":                  "deadbeef",
		}

		result := algoMapToStruct(input)
		require.NotNil(t, result)
		assert.Equal(t, []string{"curve25519-sha256", "diffie-hellman-group14-sha256"}, result.KexAlgorithms)
		assert.Equal(t, []string{"ssh-ed25519", "rsa-sha2-512"}, result.ServerHostKeyAlgorithms)
		assert.Equal(t, []string{"aes128-ctr", "aes256-ctr"}, result.CiphersClientToServer)
		assert.Equal(t, []string{"aes128-ctr", "aes256-ctr"}, result.CiphersServerToClient)
		assert.Equal(t, []string{"hmac-sha2-256"}, result.MACsClientToServer)
		assert.Equal(t, []string{"hmac-sha2-256"}, result.MACsServerToClient)
		assert.Equal(t, []string{"none"}, result.CompressionClientToServer)
		assert.Equal(t, []string{"none"}, result.CompressionServerToClient)
	})

	t.Run("nil map returns nil", func(t *testing.T) {
		assert.Nil(t, algoMapToStruct(nil))
	})

	t.Run("missing keys produce nil slices", func(t *testing.T) {
		result := algoMapToStruct(map[string]string{
			"KexAlgos": "curve25519-sha256",
		})
		require.NotNil(t, result)
		assert.Equal(t, []string{"curve25519-sha256"}, result.KexAlgorithms)
		assert.Nil(t, result.ServerHostKeyAlgorithms)
		assert.Nil(t, result.CiphersClientToServer)
	})
}
