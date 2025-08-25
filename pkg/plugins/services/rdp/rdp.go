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
	"crypto/tls"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared/ntlm"
	"net"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

type Plugin struct{}

const RDP = "rdp"

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// checkSignature checks if a given response matches the expected signature for
// the response
func checkSignature(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// getOperatingSystemSignatures returns operating system specific signatures
// for the RDP service.
func getOperatingSystemSignatures() map[string][]byte {
	Windows2000 := []byte{
		0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	WindowsServer2003 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows7OrServer2008R2 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x09, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008R2DC := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows10 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2012Or8 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x0f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2016or2019 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
	}

	signatures := map[string][]byte{
		"Windows 2000":                Windows2000,
		"Windows Server 2003":         WindowsServer2003,
		"Windows Server 2008":         WindowsServer2008,
		"Windows 7 or Server 2008 R2": Windows7OrServer2008R2,
		"Windows Server 2008 R2 DC":   WindowsServer2008R2DC,
		"Windows 10":                  Windows10,
		"Windows 8 or Server 2012":    WindowsServer2012Or8,
		"Windows Server 2016 or 2019": WindowsServer2016or2019,
	}

	return signatures
}

// checkIsRDPGeneric leverages a generic RDP signature to identify if the
// target port is running the RDP service.
func checkRDP(response []byte) bool {
	GenericRDPSignature := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	signature := GenericRDPSignature
	signatureLength := len(GenericRDPSignature)

	if len(response) < signatureLength {
		return false
	}

	responseSlice := response[:signatureLength]
	tof := checkSignature(responseSlice, signature)
	return tof
}

// guessOS tries to leverage operating system specific signatures to identify
// if the target port is running a specific operating system.
func guessOS(response []byte) (bool, string) {
	signatures := getOperatingSystemSignatures()
	for fingerprint, signature := range signatures {
		signatureLength := len(signature)
		if len(response) < signatureLength {
			continue
		}

		responseSlice := response[:signatureLength]
		tof := checkSignature(responseSlice, signature)
		if tof {
			return true, fingerprint
		}
	}

	return false, ""
}

func DetectRDP(conn net.Conn, timeout time.Duration) (*ServiceRDP, bool, error) {

	payload := ServiceRDP{}

	InitialConnectionPacket := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b,
		0x00, 0x00, 0x00,
	}

	response, err := shared.SendRecv(conn, InitialConnectionPacket, timeout)
	if err != nil {
		return &payload, false, err
	}
	if len(response) == 0 {
		return &payload, true, &shared.ServerNotEnable{}
	}

	isRDP := checkRDP(response)
	if isRDP {
		success, osFingerprint := guessOS(response)
		if success {
			payload.OSFingerprint = osFingerprint
		}

		return &payload, true, nil
	}
	return &payload, true, &shared.InvalidResponseError{Service: RDP}
}

func DetectRDPAuth(conn net.Conn, timeout time.Duration) (*ServiceRDP, bool, error) {
	info := ServiceRDP{}

	NegotiatePacket := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
		// Signature
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		// Message Type
		0x01, 0x00, 0x00, 0x00,
		// Negotiate Flags
		0xF7, 0xBA, 0xDB, 0xE2,
		// Domain Name Fields
		0x00, 0x00, // DomainNameLen
		0x00, 0x00, // DomainNameMaxLen
		0x00, 0x00, 0x00, 0x00, // DomainNameBufferOffset
		// Workstation Fields
		0x00, 0x00, // WorkstationLen
		0x00, 0x00, // WorkstationMaxLen
		0x00, 0x00, 0x00, 0x00, // WorkstationBufferOffset
		// Version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	response, err := shared.SendRecv(conn, NegotiatePacket, timeout)
	if err != nil {
		return nil, false, err
	}

	targetInfo, err := ntlm.ParseChallenge(response)
	if err != nil {
		return nil, false, nil
	}

	info.OSVersion = targetInfo.OSVersion
	info.TargetName = targetInfo.TargetName
	info.NetBIOSComputerName = targetInfo.NetBIOSComputerName
	info.NetBIOSDomainName = targetInfo.NetBIOSDomainName
	info.DNSComputerName = targetInfo.DNSComputerName
	info.DNSDomainName = targetInfo.DNSDomainName
	info.ForestName = targetInfo.ForestName

	return &info, true, nil
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {

	var detect func(net.Conn, time.Duration) (*ServiceRDP, bool, error)
	if _, isTLS := conn.Conn.(*tls.Conn); isTLS {
		detect = DetectRDPAuth
	} else {
		detect = DetectRDP
	}

	fingerprint, detected, err := detect(conn, timeout)
	if !detected {
		return nil, err
	}

	if err != nil {
		return nil, nil
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
