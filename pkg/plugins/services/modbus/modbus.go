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

package modbus

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
)

const (
	ModbusHeaderLength      = 7
	ModbusDiscreteInputCode = 0x02
	ModbusErrorAddend       = 0x80

	ModbusFCReadDeviceID   = 0x2B
	ModbusFCReportServerID = 0x11
	ModbusMEITypeDeviceID  = 0x0E
	ModbusUnitID           = 0x01

	ObjVendorName          = 0x00
	ObjProductCode         = 0x01
	ObjMajorMinorRevision  = 0x02
	ObjVendorURL           = 0x03
	ObjProductName         = 0x04
	ObjModelName           = 0x05
	ObjUserApplicationName = 0x06
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

const MODBUS = "modbus"

// newTransactionID generates a random 2-byte Modbus transaction ID.
func newTransactionID() ([]byte, error) {
	txnID := make([]byte, 2)
	_, err := rand.Read(txnID)
	if err != nil {
		return nil, &shared.RandomizeError{Message: "Transaction ID"}
	}
	return txnID, nil
}

// buildMBAPRequest constructs a Modbus TCP (MBAP) frame:
// [TransactionID:2][ProtocolID:2=0x0000][Length:2=1+len(pdu)][UnitID:1][PDU...]
func buildMBAPRequest(txnID []byte, unitID byte, pdu []byte) []byte {
	length := uint16(1 + len(pdu)) // UnitID + PDU
	buf := make([]byte, 0, 7+len(pdu))
	buf = append(buf, txnID...)
	buf = append(buf, 0x00, 0x00) // protocol ID
	buf = append(buf, byte(length>>8), byte(length&0xFF))
	buf = append(buf, unitID)
	buf = append(buf, pdu...)
	return buf
}

// validateMBAPResponse checks that the response has a valid MBAP header
// matching the transaction ID and protocol ID. Returns the PDU (bytes after
// the 7-byte header) or nil if validation fails.
func validateMBAPResponse(response, txnID []byte) []byte {
	if len(response) < 8 { // need at least header + 1 byte PDU
		return nil
	}
	if !bytes.Equal(response[:2], txnID) {
		return nil
	}
	if response[2] != 0x00 || response[3] != 0x00 { // protocol ID must be 0
		return nil
	}
	pduLen := int(binary.BigEndian.Uint16(response[4:6])) - 1 // subtract UnitID byte
	if pduLen < 1 || len(response) < 7+pduLen {
		return nil
	}
	return response[7 : 7+pduLen]
}

// isPrintableASCII returns true if all bytes are printable ASCII (0x20-0x7E).
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// deviceIDObjects holds parsed objects from Read Device Identification responses.
type deviceIDObjects struct {
	objects         map[byte]string
	conformityLevel byte
}

// probeDeviceIdentification sends FC 0x2B / MEI 0x0E (Read Device Identification)
// to retrieve vendor, product, and model information. It performs two passes:
// category 0x01 (basic objects 0-2) and category 0x02 (regular objects 3-6).
// Returns nil on any failure — this is purely enrichment.
func probeDeviceIdentification(conn net.Conn, timeout time.Duration) *deviceIDObjects {
	result := &deviceIDObjects{
		objects: make(map[byte]string),
	}

	// Two categories: basic (0x01) and regular (0x02)
	for _, category := range []byte{0x01, 0x02} {
		nextObjectID := byte(0x00)
		if category == 0x02 {
			nextObjectID = ObjVendorURL // start at object 3 for regular category
		}

		for iteration := 0; iteration < 4; iteration++ {
			txnID, err := newTransactionID()
			if err != nil {
				return result
			}

			pdu := []byte{ModbusFCReadDeviceID, ModbusMEITypeDeviceID, category, nextObjectID}
			request := buildMBAPRequest(txnID, ModbusUnitID, pdu)

			response, err := shared.SendRecv(conn, request, timeout)
			if err != nil || len(response) == 0 {
				break // this category failed, try next
			}

			respPDU := validateMBAPResponse(response, txnID)
			if respPDU == nil {
				break
			}

			// Check for exception response (function code + 0x80)
			if len(respPDU) >= 2 && respPDU[0] == ModbusFCReadDeviceID+ModbusErrorAddend {
				break
			}

			// Expected response: [0x2B][0x0E][DeviceIDCode][ConformityLevel][MoreFollows][NextObjId][NumObjects][Objects...]
			if len(respPDU) < 7 || respPDU[0] != ModbusFCReadDeviceID || respPDU[1] != ModbusMEITypeDeviceID {
				break
			}

			conformityLevel := respPDU[3]
			if conformityLevel > result.conformityLevel {
				result.conformityLevel = conformityLevel
			}
			moreFollows := respPDU[4]
			nextObjectID = respPDU[5]
			numObjects := int(respPDU[6])

			// Parse objects
			offset := 7
			for i := 0; i < numObjects; i++ {
				if offset+2 > len(respPDU) {
					break
				}
				objID := respPDU[offset]
				objLen := int(respPDU[offset+1])
				offset += 2
				if offset+objLen > len(respPDU) {
					break
				}
				result.objects[objID] = string(respPDU[offset : offset+objLen])
				offset += objLen
			}

			if moreFollows == 0x00 {
				break // no more data for this category
			}
		}
	}

	if len(result.objects) == 0 && result.conformityLevel == 0 {
		return nil
	}
	return result
}

// serverIDResult holds parsed data from Report Server ID (FC 0x11).
type serverIDResult struct {
	serverID     string
	runIndicator string
	serverInfo   string
}

// probeReportServerID sends FC 0x11 (Report Server ID) and parses the response.
// Response PDU: [0x11][ByteCount][ServerID:1][RunIndicator:1][AdditionalData...]
// Returns nil on any failure — this is purely enrichment.
func probeReportServerID(conn net.Conn, timeout time.Duration) *serverIDResult {
	txnID, err := newTransactionID()
	if err != nil {
		return nil
	}

	pdu := []byte{ModbusFCReportServerID}
	request := buildMBAPRequest(txnID, ModbusUnitID, pdu)

	response, err := shared.SendRecv(conn, request, timeout)
	if err != nil || len(response) == 0 {
		return nil
	}

	respPDU := validateMBAPResponse(response, txnID)
	if respPDU == nil {
		return nil
	}

	// Check for exception response
	if len(respPDU) >= 2 && respPDU[0] == ModbusFCReportServerID+ModbusErrorAddend {
		return nil
	}

	// Valid response: [0x11][ByteCount][Data...]
	if len(respPDU) < 2 || respPDU[0] != ModbusFCReportServerID {
		return nil
	}

	byteCount := int(respPDU[1])
	if byteCount < 2 || len(respPDU) < 2+byteCount {
		return nil
	}

	data := respPDU[2 : 2+byteCount]
	result := &serverIDResult{
		serverID: fmt.Sprintf("0x%02x", data[0]),
	}

	switch data[1] {
	case 0xFF:
		result.runIndicator = "on"
	case 0x00:
		result.runIndicator = "off"
	default:
		result.runIndicator = fmt.Sprintf("0x%02x", data[1])
	}

	if len(data) > 2 {
		additional := data[2:]
		if isPrintableASCII(additional) {
			result.serverInfo = string(additional)
		} else {
			result.serverInfo = fmt.Sprintf("0x%x", additional)
		}
	}

	return result
}

// Run identifies Modbus TCP services.
//
// modbus is a communications standard for connecting industrial devices.
// modbus can be carried over a number of frame formats; this program identifies
// modbus over TCP.
//
// Detection phase: sends a Read Discrete Input (FC 0x02) request and validates
// both success and error responses. This is the least disruptive read primitive.
//
// Enrichment phase: if detected, probes for device identification (FC 0x2B/MEI 0x0E)
// and server ID (FC 0x11). These are read-only and safe. Failures are silently
// ignored — the service was already confirmed.
//
// Initial testing done with `docker run -it -p 502:5020 oitc/modbus-server:latest`
// The default TCP port is 502, but this is unofficial.
func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// --- Detection phase: FC 0x02 (Read Discrete Input) ---
	transactionID, err := newTransactionID()
	if err != nil {
		return nil, err
	}

	// Read Discrete Input request PDU:
	// [FC=0x02][StartAddr=0x0000][Quantity=0x0001]
	detectionPDU := []byte{
		ModbusDiscreteInputCode,
		0x00, 0x00, // starting address
		0x00, 0x01, // read one bit
	}
	requestBytes := buildMBAPRequest(transactionID, ModbusUnitID, detectionPDU)

	response, err := shared.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Validate detection response
	detected := false
	if bytes.Equal(response[:2], transactionID) {
		if response[ModbusHeaderLength] == ModbusDiscreteInputCode {
			// Successful read: byte count == 1 and high 7 bits are zero
			if response[ModbusHeaderLength+1] == 1 && (response[ModbusHeaderLength+2]>>1) == 0x00 {
				detected = true
			}
		} else if response[ModbusHeaderLength] == ModbusDiscreteInputCode+ModbusErrorAddend {
			// Error response still confirms it's Modbus
			detected = true
		}
	}

	if !detected {
		return nil, nil
	}

	// --- Enrichment phase ---
	payload := ServiceModbus{}

	// Probe 1: Read Device Identification (FC 0x2B / MEI 0x0E)
	if devID := probeDeviceIdentification(conn, timeout); devID != nil {
		payload.VendorName = devID.objects[ObjVendorName]
		payload.ProductCode = devID.objects[ObjProductCode]
		payload.MajorMinorRevision = devID.objects[ObjMajorMinorRevision]
		payload.VendorURL = devID.objects[ObjVendorURL]
		payload.ProductName = devID.objects[ObjProductName]
		payload.ModelName = devID.objects[ObjModelName]
		payload.UserApplicationName = devID.objects[ObjUserApplicationName]
		payload.ConformityLevel = int(devID.conformityLevel)
	}

	// Probe 2: Report Server ID (FC 0x11)
	if srvID := probeReportServerID(conn, timeout); srvID != nil {
		payload.ServerID = srvID.serverID
		payload.RunIndicator = srvID.runIndicator
		payload.ServerInfo = srvID.serverInfo
	}

	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return MODBUS
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 400
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{502}
}
