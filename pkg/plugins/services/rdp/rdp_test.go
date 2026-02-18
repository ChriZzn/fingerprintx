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

package rdp

import (
	"testing"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
)

func TestRDP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "rdp",
			Port:        3389,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "scottyhardy/docker-remote-desktop",
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

func TestParseX224Response(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected negotiationResult
	}{
		{
			name:     "empty response",
			input:    []byte{},
			expected: negotiationResult{},
		},
		{
			name:     "too short",
			input:    []byte{0x03, 0x00, 0x00},
			expected: negotiationResult{},
		},
		{
			name: "non-RDP (wrong TPKT version)",
			input: []byte{
				0x04, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
			},
			expected: negotiationResult{},
		},
		{
			name: "non-RDP (wrong X.224 type)",
			input: []byte{
				0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x12, 0x34, 0x00,
			},
			expected: negotiationResult{},
		},
		{
			name: "Windows 2000 (no negotiation data)",
			input: []byte{
				0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
			},
			expected: negotiationResult{detected: true},
		},
		{
			name: "CredSSP selected",
			input: []byte{
				0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
				0x02, 0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
			},
			expected: negotiationResult{
				detected:         true,
				hasNegData:       true,
				selectedProtocol: protocolHybrid,
				flags:            0x1f,
			},
		},
		{
			name: "TLS selected",
			input: []byte{
				0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
				0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
			},
			expected: negotiationResult{
				detected:         true,
				hasNegData:       true,
				selectedProtocol: protocolSSL,
			},
		},
		{
			name: "Standard RDP selected",
			input: []byte{
				0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
				0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expected: negotiationResult{
				detected:         true,
				hasNegData:       true,
				selectedProtocol: protocolRDP,
			},
		},
		{
			name: "CredSSP with Early User Auth (HYBRID_EX)",
			input: []byte{
				0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
				0x02, 0x1f, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
			},
			expected: negotiationResult{
				detected:         true,
				hasNegData:       true,
				selectedProtocol: protocolHybridEx,
				flags:            0x1f,
			},
		},
		{
			name: "Negotiation failure",
			input: []byte{
				0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
				0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
			},
			expected: negotiationResult{
				detected:    true,
				hasNegData:  true,
				isFailure:   true,
				failureCode: 0x02,
			},
		},
		{
			name: "Truncated negotiation data",
			input: []byte{
				0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
				0x02, 0x1f, 0x08, // only 3 of 8 negotiation bytes
			},
			expected: negotiationResult{detected: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseX224Response(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestOsFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Exact matches
		{"Server 2019", "10.0.17763", "Windows 10 1809 / Server 2019"},
		{"Server 2022", "10.0.20348", "Windows Server 2022"},
		{"Windows 11 22H2", "10.0.22621", "Windows 11 22H2"},
		{"Server 2025", "10.0.26100", "Windows 11 24H2 / Server 2025"},
		{"Win7 SP1", "6.1.7601", "Windows 7 SP1 / Server 2008 R2 SP1"},
		{"Win8.1", "6.3.9600", "Windows 8.1 / Server 2012 R2"},
		{"Server 2016", "10.0.14393", "Windows 10 1607 / Server 2016"},

		// Prefix fallback
		{"Unknown Win10 build", "10.0.99999", "Windows 10+"},
		{"Unknown 6.1 build", "6.1.1234", "Windows 7 / Server 2008 R2"},
		{"Windows XP", "5.1.2600", "Windows XP"},
		{"Windows 2000", "5.0.2195", "Windows 2000"},
		{"Server 2003", "5.2.3790", "Windows Server 2003"},

		// Unknown
		{"Completely unknown", "99.99.99999", ""},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := osFingerprint(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
