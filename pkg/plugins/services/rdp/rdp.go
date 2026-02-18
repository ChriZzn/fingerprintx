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
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared/ntlm"
)

type Plugin struct{}

const RDP = "rdp"

// X.224 / RDP negotiation constants
const (
	tpktVersion = 0x03
	x224CCType  = 0xd0

	negTypeResponse = 0x02 // TYPE_RDP_NEG_RSP
	negTypeFailure  = 0x03 // TYPE_RDP_NEG_FAILURE

	protocolRDP      uint32 = 0x00000000 // Standard RDP Security
	protocolSSL      uint32 = 0x00000001 // TLS
	protocolHybrid   uint32 = 0x00000002 // CredSSP (NLA)
	protocolRDSTLS   uint32 = 0x00000004 // RDSTLS
	protocolHybridEx uint32 = 0x00000008 // CredSSP with Early User Authorization
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// negotiationResult holds parsed fields from an X.224 Connection Confirm response.
type negotiationResult struct {
	detected         bool
	hasNegData       bool
	isFailure        bool
	selectedProtocol uint32
	failureCode      uint32
	flags            byte
}

// parseX224Response parses a TPKT + X.224 Connection Confirm response and
// extracts any RDP Negotiation Response or Failure data.
// Returns a zero-value negotiationResult if the response is not a valid X.224 CC.
func parseX224Response(response []byte) negotiationResult {
	var result negotiationResult

	// Minimum: TPKT header (4) + X.224 CC base header (7) = 11 bytes
	// X.224 CC base: length indicator (1) + type (1) + dst ref (2) + src ref (2) + class (1)
	if len(response) < 11 {
		return result
	}

	// Validate TPKT version
	if response[0] != tpktVersion {
		return result
	}

	// Validate X.224 CC type (upper nibble)
	if response[5]&0xf0 != x224CCType {
		return result
	}

	result.detected = true

	// Check for optional RDP Negotiation data after the 6-byte CC base header.
	// The length indicator (byte 4) counts bytes after itself; CC base is 6 bytes.
	lengthIndicator := int(response[4])
	if lengthIndicator <= 6 {
		return result // Valid RDP but no negotiation data (e.g., Windows 2000)
	}

	// Negotiation data is 8 bytes starting at byte 11
	if len(response) < 19 {
		return result // Truncated negotiation data
	}

	negType := response[11]
	result.hasNegData = true
	result.flags = response[12]

	switch negType {
	case negTypeResponse:
		result.selectedProtocol = binary.LittleEndian.Uint32(response[15:19])
	case negTypeFailure:
		result.isFailure = true
		result.failureCode = binary.LittleEndian.Uint32(response[15:19])
	}

	return result
}

// selectedProtocolString maps an RDP negotiation selected protocol value to a
// human-readable name.
func selectedProtocolString(protocol uint32) string {
	switch protocol {
	case protocolRDP:
		return "Standard RDP"
	case protocolSSL:
		return "TLS"
	case protocolHybrid:
		return "CredSSP"
	case protocolRDSTLS:
		return "RDSTLS"
	case protocolHybridEx:
		return "CredSSP with Early User Auth"
	default:
		return fmt.Sprintf("Unknown (0x%08x)", protocol)
	}
}

// osFingerprint maps an NTLM OS version string ("major.minor.build") to a
// Windows version name. Returns empty string if unknown.
func osFingerprint(osVersion string) string {
	exact := map[string]string{
		"6.0.6000":   "Windows Vista / Server 2008",
		"6.0.6001":   "Windows Vista SP1 / Server 2008 SP1",
		"6.0.6002":   "Windows Vista SP2 / Server 2008 SP2",
		"6.1.7600":   "Windows 7 / Server 2008 R2",
		"6.1.7601":   "Windows 7 SP1 / Server 2008 R2 SP1",
		"6.2.9200":   "Windows 8 / Server 2012",
		"6.3.9600":   "Windows 8.1 / Server 2012 R2",
		"10.0.10240": "Windows 10 1507",
		"10.0.10586": "Windows 10 1511",
		"10.0.14393": "Windows 10 1607 / Server 2016",
		"10.0.15063": "Windows 10 1703",
		"10.0.16299": "Windows 10 1709",
		"10.0.17134": "Windows 10 1803",
		"10.0.17763": "Windows 10 1809 / Server 2019",
		"10.0.18362": "Windows 10 1903",
		"10.0.18363": "Windows 10 1909",
		"10.0.19041": "Windows 10 2004",
		"10.0.19042": "Windows 10 20H2",
		"10.0.19043": "Windows 10 21H1",
		"10.0.19044": "Windows 10 21H2",
		"10.0.19045": "Windows 10 22H2",
		"10.0.20348": "Windows Server 2022",
		"10.0.22000": "Windows 11 21H2",
		"10.0.22621": "Windows 11 22H2",
		"10.0.22631": "Windows 11 23H2",
		"10.0.26100": "Windows 11 24H2 / Server 2025",
	}
	if name, ok := exact[osVersion]; ok {
		return name
	}

	// Prefix fallback (major.minor)
	prefixes := map[string]string{
		"5.0.":  "Windows 2000",
		"5.1.":  "Windows XP",
		"5.2.":  "Windows Server 2003",
		"6.0.":  "Windows Vista / Server 2008",
		"6.1.":  "Windows 7 / Server 2008 R2",
		"6.2.":  "Windows 8 / Server 2012",
		"6.3.":  "Windows 8.1 / Server 2012 R2",
		"10.0.": "Windows 10+",
	}
	for p, name := range prefixes {
		if strings.HasPrefix(osVersion, p) {
			return name
		}
	}

	return ""
}

// probeCredSSPNTLM sends a CredSSP TSRequest containing an NTLM Type 1
// (Negotiate) message and parses the NTLM Type 2 (Challenge) from the response.
// Returns nil on any error.
func probeCredSSPNTLM(conn net.Conn, timeout time.Duration) *ntlm.TargetInfo {
	negotiatePacket := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1,
		0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
		// NTLMSSP signature
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		// Message Type 1 (Negotiate)
		0x01, 0x00, 0x00, 0x00,
		// Negotiate Flags
		0xF7, 0xBA, 0xDB, 0xE2,
		// Domain Name Fields (empty)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Workstation Fields (empty)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Version (empty)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	response, err := shared.SendRecv(conn, negotiatePacket, timeout)
	if err != nil {
		return nil
	}

	targetInfo, err := ntlm.ParseChallenge(response)
	if err != nil {
		return nil
	}

	return targetInfo
}

// populateNTLMInfo copies NTLM target information into the ServiceRDP metadata
// and derives the OS fingerprint from the version string.
func populateNTLMInfo(info *ServiceRDP, targetInfo *ntlm.TargetInfo) {
	info.OSVersion = targetInfo.OSVersion
	info.OSFingerprint = osFingerprint(targetInfo.OSVersion)
	info.TargetName = targetInfo.TargetName
	info.NetBIOSComputerName = targetInfo.NetBIOSComputerName
	info.NetBIOSDomainName = targetInfo.NetBIOSDomainName
	info.DNSComputerName = targetInfo.DNSComputerName
	info.DNSDomainName = targetInfo.DNSDomainName
	info.ForestName = targetInfo.ForestName
}

// DetectRDP performs X.224 Connection Request negotiation on a raw TCP
// connection. It parses the X.224 Connection Confirm response structurally,
// extracts security protocol information, and attempts NTLM extraction when
// the server selects CredSSP (by upgrading to TLS first).
//
// Note: this function may upgrade conn to TLS when CredSSP is negotiated.
func DetectRDP(conn *plugins.FingerprintConn, timeout time.Duration) (*ServiceRDP, bool, error) {
	connectionRequest := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b,
		0x00, 0x00, 0x00,
	}

	response, err := shared.SendRecv(conn, connectionRequest, timeout)
	if err != nil {
		return nil, false, err
	}
	if len(response) == 0 {
		return nil, false, nil
	}

	result := parseX224Response(response)
	if !result.detected {
		return nil, false, nil
	}

	payload := &ServiceRDP{}

	if result.hasNegData {
		if result.isFailure {
			// Server rejected our requested protocols; falls back to Standard RDP
			payload.SecurityProtocol = "Standard RDP"
		} else {
			payload.SecurityProtocol = selectedProtocolString(result.selectedProtocol)
			payload.NLARequired = result.selectedProtocol == protocolHybrid ||
				result.selectedProtocol == protocolHybridEx

			// For CredSSP: upgrade to TLS, then probe NTLM for OS/domain info
			if payload.NLARequired && conn.TLS() == nil {
				if _, ok := conn.Conn.(*net.TCPConn); ok {
					conn.Upgrade()
					if conn.TLS() != nil {
						if targetInfo := probeCredSSPNTLM(conn, timeout); targetInfo != nil {
							populateNTLMInfo(payload, targetInfo)
						}
					}
				}
			}
		}
	}

	return payload, true, nil
}

// DetectRDPAuth probes an already-TLS connection for NTLM authentication
// information via CredSSP.
func DetectRDPAuth(conn net.Conn, timeout time.Duration) (*ServiceRDP, bool, error) {
	targetInfo := probeCredSSPNTLM(conn, timeout)
	if targetInfo == nil {
		return nil, false, nil
	}

	info := &ServiceRDP{}
	populateNTLMInfo(info, targetInfo)
	return info, true, nil
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if conn.TLS() != nil {
		// TLS path: connection already wrapped in TLS, probe NTLM directly
		fingerprint, detected, err := DetectRDPAuth(conn, timeout)
		if !detected {
			return nil, err
		}
		return plugins.CreateServiceFrom(target, p.Name(), fingerprint, conn.TLS()), nil
	}

	// Raw TCP path: X.224 negotiation (may upgrade to TLS internally)
	fingerprint, detected, err := DetectRDP(conn, timeout)
	if !detected {
		return nil, err
	}
	return plugins.CreateServiceFrom(target, p.Name(), fingerprint, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return RDP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 89
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{3389}
}
