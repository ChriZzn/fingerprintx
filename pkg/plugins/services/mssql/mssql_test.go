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

package mssql

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMSSQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mssql",
			Port:        1433,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				if res == nil {
					return false
				}
				raw, err := json.Marshal(res.Metadata)
				if err != nil {
					return false
				}
				var meta ServiceMSSQL
				if err := json.Unmarshal(raw, &meta); err != nil {
					return false
				}
				// SQL Server 2019 should report major version 15
				if !strings.HasPrefix(meta.Version, "15.") {
					return false
				}
				if meta.ProductName != "SQL Server 2019" {
					return false
				}
				if meta.Encryption == "" {
					return false
				}
				return true
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mcr.microsoft.com/mssql/server",
				Tag:        "2019-latest",
				Env: []string{
					"ACCEPT_EULA=Y",
					"SA_PASSWORD=yourStrong(!)Password",
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

func TestEncryptionString(t *testing.T) {
	tests := []struct {
		input    byte
		expected string
	}{
		{0x00, "off"},
		{0x01, "on"},
		{0x02, "not_supported"},
		{0x03, "required"},
		{0xAA, "unknown(0xaa)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, encryptionString(tt.input))
	}
}

func TestMARSString(t *testing.T) {
	tests := []struct {
		input    byte
		expected string
	}{
		{0x00, "off"},
		{0x01, "on"},
		{0x42, "unknown(0x42)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, marsString(tt.input))
	}
}

func TestProductName(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"16.0.1000", "SQL Server 2022"},
		{"15.0.2000", "SQL Server 2019"},
		{"14.0.3000", "SQL Server 2017"},
		{"13.0.5000", "SQL Server 2016"},
		{"12.0.6000", "SQL Server 2014"},
		{"11.0.7000", "SQL Server 2012"},
		{"10.50.6000", "SQL Server 2008"},
		{"9.0.5000", "SQL Server 2005"},
		{"8.0.2039", "SQL Server 2000"},
		{"99.0.0", ""},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, productName(tt.version), "version: %s", tt.version)
	}
}

func TestBuildLogin7WithNTLM(t *testing.T) {
	packet := buildLogin7WithNTLM()

	// TDS header checks
	require.True(t, len(packet) > 8, "packet too short")
	assert.Equal(t, byte(0x10), packet[0], "TDS type should be Login7 (0x10)")
	assert.Equal(t, byte(0x01), packet[1], "TDS status should be EOM")

	tdsLen := binary.BigEndian.Uint16(packet[2:4])
	assert.Equal(t, uint16(len(packet)), tdsLen, "TDS length field should match actual packet length")
	assert.Equal(t, byte(0x01), packet[6], "PacketID should be 1")

	// Login7 body starts at offset 8
	login7 := packet[8:]
	require.True(t, len(login7) >= 94, "Login7 body too short")

	login7Len := binary.LittleEndian.Uint32(login7[0:4])
	assert.Equal(t, uint32(len(login7)), login7Len, "Login7 length field should match actual body length")

	// OptionFlags2 should have fIntSecurity set
	assert.Equal(t, byte(0x80), login7[25], "OptionFlags2 should have fIntSecurity (0x80)")

	// SSPI offset/length (bytes 78-81 of login7 body)
	sspiOffset := binary.LittleEndian.Uint16(login7[78:80])
	sspiLen := binary.LittleEndian.Uint16(login7[80:82])
	assert.Equal(t, uint16(94), sspiOffset, "SSPI offset should point to end of fixed body")
	assert.True(t, sspiLen > 0, "SSPI length should be non-zero")

	// NTLM signature should be present at the SSPI offset
	if int(sspiOffset)+8 <= len(login7) {
		assert.Equal(t, []byte("NTLMSSP\x00"), login7[sspiOffset:sspiOffset+8], "NTLM signature should be present")
	}
}
