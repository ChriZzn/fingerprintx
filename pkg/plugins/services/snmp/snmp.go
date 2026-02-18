package snmp

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
)

const SNMP = "snmp"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Pre-encoded OID bytes for system MIB objects.
var (
	oidSysDescr    = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00} // 1.3.6.1.2.1.1.1.0
	oidSysObjectID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00} // 1.3.6.1.2.1.1.2.0
	oidSysContact  = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00} // 1.3.6.1.2.1.1.4.0
	oidSysName     = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00} // 1.3.6.1.2.1.1.5.0
	oidSysLocation = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00} // 1.3.6.1.2.1.1.6.0
)

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
		enrichV3(service, resp)
		return plugins.CreateServiceFrom(target, p.Name(), service, nil), nil
	}

	// Try SNMP v1
	if resp, err := shared.SendRecv(conn, createSNMPv1v2Packet(0x00), delay); err == nil && isValidSNMPResponse(resp) {
		service.Version = 1
		enrichV1V2(conn, service, resp, 0x00)
		return plugins.CreateServiceFrom(target, p.Name(), service, nil), nil
	}

	// Try SNMP v2c
	if resp, err := shared.SendRecv(conn, createSNMPv1v2Packet(0x01), delay); err == nil && isValidSNMPResponse(resp) {
		service.Version = 2
		enrichV1V2(conn, service, resp, 0x01)
		return plugins.CreateServiceFrom(target, p.Name(), service, nil), nil
	}

	return nil, nil
}

// parseSNMPv1v2Response parses an SNMP v1/v2c GetResponse and extracts varbinds as OID→string map.
// Structure: SEQUENCE { version, community, GetResponse(0xa2) { reqid, error-status, error-index, varbind-list } }
func parseSNMPv1v2Response(data []byte) map[string]string {
	if len(data) < 3 {
		return nil
	}
	outer, _, err := parseBERElement(data, 0)
	if err != nil || len(outer.Children) < 3 {
		return nil
	}

	// Third child is the PDU (GetResponse = 0xa2)
	pdu := outer.Children[2]
	if pdu.Tag != snmpGetResponse {
		return nil
	}
	if len(pdu.Children) < 4 {
		return nil
	}

	// Check error-status == 0
	errorStatus := parseBERInt(pdu.Children[1])
	if errorStatus != 0 {
		return nil
	}

	// Fourth child is varbind-list (SEQUENCE OF varbind)
	varbindList := pdu.Children[3]
	result := make(map[string]string)
	for _, varbind := range varbindList.Children {
		if len(varbind.Children) < 2 {
			continue
		}
		oidElem := varbind.Children[0]
		valElem := varbind.Children[1]
		if oidElem.Tag != berTagOID {
			continue
		}
		oid := decodeOID(oidElem.Data)
		val := extractSNMPValue(valElem)
		if val != "" {
			result[oid] = val
		}
	}
	return result
}

// extractSNMPValue converts a BER element to a string based on its tag.
func extractSNMPValue(elem berElement) string {
	switch elem.Tag {
	case berTagOctetString:
		return string(elem.Data)
	case berTagOID:
		return decodeOID(elem.Data)
	case berTagInteger, 0x41, 0x43: // INTEGER, Counter32, TimeTicks
		return strconv.Itoa(parseBERInt(elem))
	default:
		return ""
	}
}

// parseSNMPv3Response parses an SNMP v3 Report and extracts engine info.
// Structure: SEQUENCE { version, globalData, securityParams(OCTET STRING), scopedPDU }
// securityParams contains a nested SEQUENCE: { engineID, boots, time, user, auth, priv }
func parseSNMPv3Response(data []byte) (engineID []byte, boots, engineTime int, ok bool) {
	if len(data) < 3 {
		return nil, 0, 0, false
	}
	outer, _, err := parseBERElement(data, 0)
	if err != nil || len(outer.Children) < 3 {
		return nil, 0, 0, false
	}

	// Verify version == 3
	if parseBERInt(outer.Children[0]) != 3 {
		return nil, 0, 0, false
	}

	// Third child is securityParams (OCTET STRING wrapping a SEQUENCE)
	secParams := outer.Children[2]
	if secParams.Tag != berTagOctetString || len(secParams.Data) == 0 {
		return nil, 0, 0, false
	}

	// Parse the nested SEQUENCE inside securityParams
	inner, _, err := parseBERElement(secParams.Data, 0)
	if err != nil || len(inner.Children) < 3 {
		return nil, 0, 0, false
	}

	engineID = inner.Children[0].Data
	boots = parseBERInt(inner.Children[1])
	engineTime = parseBERInt(inner.Children[2])
	return engineID, boots, engineTime, true
}

// createMultiOIDRequest builds a GetRequest with multiple OIDs.
func createMultiOIDRequest(version byte, oids [][]byte) []byte {
	var varbinds [][]byte
	for _, oid := range oids {
		varbind := berSequence(berOID(oid), berNull())
		varbinds = append(varbinds, varbind)
	}
	varbindList := berSequence(varbinds...)
	getRequest := berContextConstructed(0, // GetRequest = context 0, constructed
		berInteger(0x7fffffff), // request ID
		berInteger(0),          // error-status
		berInteger(0),          // error-index
		varbindList,
	)
	return berSequence(
		berInteger(int(version)),
		berOctetString([]byte("public")),
		getRequest,
	)
}

// enrichV1V2 extracts metadata from the initial sysDescr response and sends
// a follow-up multi-OID request for additional system info. All best-effort.
func enrichV1V2(conn *plugins.FingerprintConn, service *ServiceSNMP, initialResp []byte, version byte) {
	// Parse sysDescr from the initial response
	varbinds := parseSNMPv1v2Response(initialResp)
	if v, ok := varbinds["1.3.6.1.2.1.1.1.0"]; ok {
		service.SysDescr = v
	}

	// Send a follow-up request for additional OIDs
	req := createMultiOIDRequest(version, [][]byte{
		oidSysObjectID,
		oidSysContact,
		oidSysName,
		oidSysLocation,
	})
	resp, err := shared.SendRecv(conn, req, delay)
	if err != nil || len(resp) == 0 {
		return
	}
	extra := parseSNMPv1v2Response(resp)
	if extra == nil {
		return
	}
	if v, ok := extra["1.3.6.1.2.1.1.2.0"]; ok {
		service.SysObjectID = v
	}
	if v, ok := extra["1.3.6.1.2.1.1.4.0"]; ok {
		service.SysContact = v
	}
	if v, ok := extra["1.3.6.1.2.1.1.5.0"]; ok {
		service.SysName = v
	}
	if v, ok := extra["1.3.6.1.2.1.1.6.0"]; ok {
		service.SysLocation = v
	}
}

// enrichV3 extracts engine info from the v3 discovery report.
func enrichV3(service *ServiceSNMP, resp []byte) {
	engineID, boots, engineTime, ok := parseSNMPv3Response(resp)
	if !ok {
		return
	}
	if len(engineID) > 0 {
		service.EngineID = hex.EncodeToString(engineID)
	}
	service.EngineBoots = boots
	service.EngineTime = engineTime
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
