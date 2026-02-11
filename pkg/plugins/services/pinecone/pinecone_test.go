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

package pinecone

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

// unmarshalMetadata is a test helper that unmarshals result.Metadata into ServicePinecone.
func unmarshalMetadata(t *testing.T, result *plugins.Service) *ServicePinecone {
	t.Helper()
	var payload ServicePinecone
	if err := json.Unmarshal(result.Metadata, &payload); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	return &payload
}

// TestBuildDetectionResult tests the buildDetectionResult function with various API versions and confidence levels
func TestBuildDetectionResult(t *testing.T) {
	tests := []struct {
		name           string
		apiVersion     string
		confidence     string
		wantCPE        string
		wantAPIVersion string
		description    string
	}{
		{
			name:           "valid API version 2025-01 with high confidence",
			apiVersion:     "2025-01",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "2025-01",
			description:    "Standard API version with high confidence should generate wildcard CPE",
		},
		{
			name:           "valid API version 2024-04 with high confidence",
			apiVersion:     "2024-04",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "2024-04",
			description:    "Different API version format should still generate wildcard CPE",
		},
		{
			name:           "empty API version with medium confidence",
			apiVersion:     "",
			confidence:     "medium",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "",
			description:    "Empty API version (secondary detection) should still generate wildcard CPE",
		},
		{
			name:           "API version 2023-12 with high confidence",
			apiVersion:     "2023-12",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "2023-12",
			description:    "Older API version should generate wildcard CPE",
		},
		{
			name:           "non-standard API version format",
			apiVersion:     "v2.0",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "v2.0",
			description:    "Non-standard version format should be stored but CPE remains wildcard",
		},
		{
			name:           "API version with extra content",
			apiVersion:     "2025-01-beta",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "2025-01-beta",
			description:    "API version with suffix should be preserved in metadata but CPE wildcard",
		},
		{
			name:           "numeric only API version",
			apiVersion:     "1",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "1",
			description:    "Simple numeric version should work with wildcard CPE",
		},
		{
			name:           "whitespace in API version",
			apiVersion:     "  2025-01  ",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "  2025-01  ",
			description:    "Whitespace preserved in API version metadata, CPE wildcard",
		},
		{
			name:           "special characters in API version",
			apiVersion:     "2025-01_rc1",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "2025-01_rc1",
			description:    "Special characters should be preserved in metadata",
		},
		{
			name:           "very long API version string",
			apiVersion:     "2025-01-production-release-candidate-1",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "2025-01-production-release-candidate-1",
			description:    "Long version strings should work",
		},
		{
			name:           "empty API version with high confidence",
			apiVersion:     "",
			confidence:     "high",
			wantCPE:        "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			wantAPIVersion: "",
			description:    "Empty version with high confidence should still work",
		},
	}

	plugin := &PINECONEPlugin{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 401,
				Header:     make(http.Header),
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.0.2.1:443"),
				Host:    "pinecone.example.com",
			}

			result, err := plugin.buildDetectionResult(target, nil, resp, tt.apiVersion, tt.confidence)

			if err != nil {
				t.Errorf("buildDetectionResult() unexpected error: %v\nDescription: %s",
					err, tt.description)
				return
			}

			if result == nil {
				t.Errorf("buildDetectionResult() returned nil result\nDescription: %s", tt.description)
				return
			}

			pineconePayload := unmarshalMetadata(t, result)

			if len(pineconePayload.CPEs) == 0 {
				t.Errorf("buildDetectionResult() CPEs array is empty\nDescription: %s", tt.description)
				return
			}

			if pineconePayload.CPEs[0] != tt.wantCPE {
				t.Errorf("buildDetectionResult() CPE = %q, want %q\nDescription: %s",
					pineconePayload.CPEs[0], tt.wantCPE, tt.description)
			}

			if pineconePayload.APIVersion != tt.wantAPIVersion {
				t.Errorf("buildDetectionResult() APIVersion = %q, want %q\nDescription: %s",
					pineconePayload.APIVersion, tt.wantAPIVersion, tt.description)
			}

			// Verify protocol name is pinecone
			if result.Protocol != PROTOCOL_NAME {
				t.Errorf("buildDetectionResult() Protocol = %q, want %q\nDescription: %s",
					result.Protocol, PROTOCOL_NAME, tt.description)
			}
		})
	}
}

// TestBuildDetectionResultCPEWildcardConsistency tests that CPE version is always wildcard
func TestBuildDetectionResultCPEWildcardConsistency(t *testing.T) {
	tests := []struct {
		name        string
		apiVersion  string
		description string
	}{
		{
			name:        "API version 2025-01",
			apiVersion:  "2025-01",
			description: "Standard API version should produce wildcard CPE",
		},
		{
			name:        "API version 2024-04",
			apiVersion:  "2024-04",
			description: "Different API version should produce wildcard CPE",
		},
		{
			name:        "empty API version",
			apiVersion:  "",
			description: "Empty API version should produce wildcard CPE",
		},
		{
			name:        "semantic version format",
			apiVersion:  "1.2.3",
			description: "Semantic version format should produce wildcard CPE",
		},
		{
			name:        "random string",
			apiVersion:  "random-version",
			description: "Random version string should produce wildcard CPE",
		},
	}

	plugin := &PINECONEPlugin{}
	expectedCPE := "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 401,
				Header:     make(http.Header),
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.0.2.1:443"),
				Host:    "pinecone.example.com",
			}

			result, err := plugin.buildDetectionResult(target, nil, resp, tt.apiVersion, "high")

			if err != nil {
				t.Errorf("buildDetectionResult() unexpected error: %v\nDescription: %s",
					err, tt.description)
				return
			}

			pineconePayload := unmarshalMetadata(t, result)

			if len(pineconePayload.CPEs) == 0 {
				t.Errorf("buildDetectionResult() CPEs array is empty\nDescription: %s", tt.description)
				return
			}

			actualCPE := pineconePayload.CPEs[0]
			if actualCPE != expectedCPE {
				t.Errorf("buildDetectionResult() CPE = %q, want %q (wildcard version always)\nDescription: %s",
					actualCPE, expectedCPE, tt.description)
			}
		})
	}
}

// TestPineconePluginInterface tests the plugin interface methods
func TestPineconePluginInterface(t *testing.T) {
	plugin := &PINECONEPlugin{}

	t.Run("Name", func(t *testing.T) {
		expected := "pinecone"
		if name := plugin.Name(); name != expected {
			t.Errorf("Name() = %q, want %q", name, expected)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCP {
			t.Errorf("Type() = %v, want TCP (%v)", pluginType, plugins.TCP)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		expectedPriority := 50
		if priority != expectedPriority {
			t.Errorf("Priority() = %d, want %d", priority, expectedPriority)
		}
	})

	t.Run("Ports contains 443", func(t *testing.T) {
		ports := plugin.Ports()
		found := false
		for _, p := range ports {
			if p == 443 {
				found = true
				break
			}
		}
		if !found {
			t.Error("Ports() should contain 443 (Pinecone default port)")
		}
	})
}

// TestHeaderConstants tests that header constant values are correct
func TestHeaderConstants(t *testing.T) {
	tests := []struct {
		name        string
		constant    string
		expected    string
		description string
	}{
		{
			name:        "PROTOCOL_NAME",
			constant:    PROTOCOL_NAME,
			expected:    "pinecone",
			description: "Protocol name should be 'pinecone'",
		},
		{
			name:        "HEADER_API_VERSION",
			constant:    HEADER_API_VERSION,
			expected:    "X-Pinecone-Api-Version",
			description: "Primary detection header for API version",
		},
		{
			name:        "HEADER_AUTH_REJECTED",
			constant:    HEADER_AUTH_REJECTED,
			expected:    "X-Pinecone-Auth-Rejected-Reason",
			description: "Secondary detection header for auth rejection",
		},
		{
			name:        "USERAGENT",
			constant:    USERAGENT,
			expected:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
			description: "User agent string for HTTP requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Constant %s = %q, want %q\nDescription: %s",
					tt.name, tt.constant, tt.expected, tt.description)
			}
		})
	}
}

// TestDefaultPort tests the DEFAULT_PORT constant
func TestDefaultPort(t *testing.T) {
	expectedPort := uint16(443)
	actualPort := uint16(DEFAULT_PORT)

	if actualPort != expectedPort {
		t.Errorf("DEFAULT_PORT = %d, want %d (HTTPS port for Pinecone)", actualPort, expectedPort)
	}
}

// TestHeaderCaseInsensitivity documents expected behavior for HTTP header case handling
func TestHeaderCaseInsensitivity(t *testing.T) {
	tests := []struct {
		name        string
		headerKey   string
		headerValue string
		lookupKey   string
		description string
	}{
		{
			name:        "exact case match",
			headerKey:   "X-Pinecone-Api-Version",
			headerValue: "2025-01",
			lookupKey:   "X-Pinecone-Api-Version",
			description: "Exact case match should work",
		},
		{
			name:        "lowercase lookup",
			headerKey:   "X-Pinecone-Api-Version",
			headerValue: "2025-01",
			lookupKey:   "x-pinecone-api-version",
			description: "Lowercase lookup should work (HTTP headers are case-insensitive)",
		},
		{
			name:        "uppercase lookup",
			headerKey:   "X-Pinecone-Api-Version",
			headerValue: "2025-01",
			lookupKey:   "X-PINECONE-API-VERSION",
			description: "Uppercase lookup should work (HTTP headers are case-insensitive)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 401,
				Header:     make(http.Header),
			}
			resp.Header.Set(tt.headerKey, tt.headerValue)

			actualValue := resp.Header.Get(tt.lookupKey)

			if actualValue != tt.headerValue {
				t.Errorf("Header.Get(%q) = %q, want %q\nDescription: %s",
					tt.lookupKey, actualValue, tt.headerValue, tt.description)
			}
		})
	}
}

// TestConfidenceLevels tests different confidence levels in buildDetectionResult
func TestConfidenceLevels(t *testing.T) {
	tests := []struct {
		name        string
		confidence  string
		apiVersion  string
		description string
	}{
		{
			name:        "high confidence with API version",
			confidence:  "high",
			apiVersion:  "2025-01",
			description: "Primary detection marker present (x-pinecone-api-version)",
		},
		{
			name:        "medium confidence without API version",
			confidence:  "medium",
			apiVersion:  "",
			description: "Secondary detection marker only (x-pinecone-auth-rejected-reason)",
		},
		{
			name:        "high confidence with empty API version",
			confidence:  "high",
			apiVersion:  "",
			description: "Edge case: high confidence with empty API version",
		},
		{
			name:        "custom confidence level",
			confidence:  "low",
			apiVersion:  "2025-01",
			description: "Custom confidence level should work",
		},
	}

	plugin := &PINECONEPlugin{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 401,
				Header:     make(http.Header),
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.0.2.1:443"),
				Host:    "pinecone.example.com",
			}

			result, err := plugin.buildDetectionResult(target, nil, resp, tt.apiVersion, tt.confidence)

			if err != nil {
				t.Errorf("buildDetectionResult() unexpected error: %v\nDescription: %s",
					err, tt.description)
				return
			}

			if result == nil {
				t.Errorf("buildDetectionResult() returned nil\nDescription: %s", tt.description)
				return
			}

			pineconePayload := unmarshalMetadata(t, result)

			expectedCPE := "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*"
			if len(pineconePayload.CPEs) == 0 || pineconePayload.CPEs[0] != expectedCPE {
				t.Errorf("buildDetectionResult() CPE mismatch for confidence %q\nDescription: %s",
					tt.confidence, tt.description)
			}

			if pineconePayload.APIVersion != tt.apiVersion {
				t.Errorf("buildDetectionResult() APIVersion = %q, want %q\nDescription: %s",
					pineconePayload.APIVersion, tt.apiVersion, tt.description)
			}
		})
	}
}

// TestEdgeCases tests edge cases in buildDetectionResult
func TestEdgeCases(t *testing.T) {
	plugin := &PINECONEPlugin{}

	t.Run("nil response (should not panic)", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("buildDetectionResult() panicked with nil response: %v", r)
			}
		}()

		target := plugins.Target{
			Address: netip.MustParseAddrPort("192.0.2.1:443"),
			Host:    "pinecone.example.com",
		}

		_, _ = plugin.buildDetectionResult(target, nil, nil, "2025-01", "high")
	})

	t.Run("empty target address", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 401,
			Header:     make(http.Header),
		}

		target := plugins.Target{
			Address: netip.MustParseAddrPort("0.0.0.0:0"),
			Host:    "",
		}

		result, err := plugin.buildDetectionResult(target, nil, resp, "2025-01", "high")

		if err != nil {
			t.Errorf("buildDetectionResult() unexpected error with empty target: %v", err)
			return
		}

		if result == nil {
			t.Error("buildDetectionResult() returned nil with empty target")
		}
	})

	t.Run("very large API version string", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 401,
			Header:     make(http.Header),
		}

		target := plugins.Target{
			Address: netip.MustParseAddrPort("192.0.2.1:443"),
			Host:    "pinecone.example.com",
		}

		longVersion := ""
		for i := 0; i < 100; i++ {
			longVersion += "2025-01-v1."
		}

		result, err := plugin.buildDetectionResult(target, nil, resp, longVersion, "high")

		if err != nil {
			t.Errorf("buildDetectionResult() unexpected error with long version: %v", err)
			return
		}

		if result == nil {
			t.Error("buildDetectionResult() returned nil with long version")
			return
		}

		pineconePayload := unmarshalMetadata(t, result)

		if pineconePayload.APIVersion != longVersion {
			t.Errorf("buildDetectionResult() APIVersion length = %d, want %d",
				len(pineconePayload.APIVersion), len(longVersion))
		}
	})

	t.Run("unicode in API version", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 401,
			Header:     make(http.Header),
		}

		target := plugins.Target{
			Address: netip.MustParseAddrPort("192.0.2.1:443"),
			Host:    "pinecone.example.com",
		}

		unicodeVersion := "2025-01-\u00e9-version"

		result, err := plugin.buildDetectionResult(target, nil, resp, unicodeVersion, "high")

		if err != nil {
			t.Errorf("buildDetectionResult() unexpected error with unicode version: %v", err)
			return
		}

		if result == nil {
			t.Error("buildDetectionResult() returned nil with unicode version")
			return
		}

		pineconePayload := unmarshalMetadata(t, result)

		if pineconePayload.APIVersion != unicodeVersion {
			t.Errorf("buildDetectionResult() APIVersion = %q, want %q",
				pineconePayload.APIVersion, unicodeVersion)
		}
	})
}
