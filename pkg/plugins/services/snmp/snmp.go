package snmp

import (
	"bytes"
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"time"
)

const SNMP = "snmp"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func createSNMPv1v2Packet(version byte) []byte {
	return []byte{
		0x30, 0x29, // Sequence length
		0x02, 0x01, version, // Version: 0 for v1, 1 for v2c
		0x04, 0x06, // Community string length
		0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
		0xa0, 0x1c, // GetRequest PDU
		0x02, 0x04, 0xff, 0xff, 0xff, 0xff, // Request ID
		0x02, 0x01, 0x00, // Error status
		0x02, 0x01, 0x00, // Error index
		0x30, 0x0e, // Variable bindings
		0x30, 0x0c, // Variable binding
		0x06, 0x08, // OID length
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // system.sysDescr.0
		0x05, 0x00, // Null value
	}
}

func createSNMPv3Packet() []byte {
	return []byte{
		0x30, 0x3a, // Sequence length
		0x02, 0x01, 0x03, // Version: 3
		0x30, 0x0f, // msgGlobalData
		0x02, 0x02, 0x4a, 0x69, // Message ID
		0x02, 0x03, 0x00, 0xff, 0xe3, // Max message size
		0x04, 0x01, 0x04, // Message flags
		0x02, 0x01, 0x03, // Security model (USM)
		0x04, 0x10, // Security parameters length
		0x30, 0x0e, // Security parameters sequence
		0x04, 0x00, // msgAuthoritativeEngineID: empty
		0x02, 0x01, 0x00, // msgAuthoritativeEngineBoots: 0
		0x02, 0x01, 0x00, // msgAuthoritativeEngineTime: 0
		0x04, 0x00, // msgUserName: empty
		0x04, 0x00, // msgAuthenticationParameters: empty
		0x04, 0x00, // msgPrivacyParameters: empty
		0x30, 0x12, // ScopedPDU
		0x04, 0x00, // contextEngineID: empty
		0x04, 0x00, // contextName: empty
		0xa0, 0x0c, // PDU type: GET
		0x02, 0x02, 0x37, 0xf0, // request-id
		0x02, 0x01, 0x00, // error-status
		0x02, 0x01, 0x00, // error-index
		0x30, 0x00, // variable-bindings
	}
}

const delay = 500 * time.Millisecond

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	service := &ServiceSNMP{}

	// Try SNMP v3
	if resp, err := shared.SendRecv(conn, createSNMPv3Packet(), delay); err == nil && isValidSNMPv3Response(resp) {
		service.Version = 3
		return plugins.CreateServiceFrom(target, p.Name(), service, nil), nil
	}

	// Try SNMP v1
	if resp, err := shared.SendRecv(conn, createSNMPv1v2Packet(0x00), delay); err == nil && isValidSNMPResponse(resp) {
		service.Version = 1
		return plugins.CreateServiceFrom(target, p.Name(), service, nil), nil
	}

	// Try SNMP v2c
	if resp, err := shared.SendRecv(conn, createSNMPv1v2Packet(0x01), delay); err == nil && isValidSNMPResponse(resp) {
		service.Version = 2
		return plugins.CreateServiceFrom(target, p.Name(), service, nil), nil
	}

	return nil, nil
}

func isValidSNMPResponse(response []byte) bool {
	// Check for minimum length and SNMP sequence identifier
	if len(response) < 3 || response[0] != 0x30 {
		return false
	}

	// Look for typical SNMP response elements
	return bytes.Contains(response, []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00})
}

func isValidSNMPv3Response(response []byte) bool {
	return len(response) > 10 && response[0] == 0x30 && response[4] == 0x03 // Version 3 check
}

func (p *Plugin) Name() string {
	return SNMP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 81
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{161}
}
