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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared/ntlm"
)

// Potential values for PLOptionToken
const (
	VERSION         int  = 0
	ENCRYPTION      int  = 1
	INSTOPT         int  = 2
	THREADID        int  = 3
	MARS            int  = 4
	TRACEID         int  = 5
	FEDAUTHREQUIRED int  = 6
	NONCEOPT        int  = 7
	TERMINATOR      byte = 0xFF
)

type OptionToken struct {
	PLOptionToken  uint32
	PLOffset       uint32
	PLOptionLength uint32
	PLOptionData   []byte // the raw data associated with the option
}

type Plugin struct{}

type Data struct {
	Version      string
	Encryption   byte
	InstanceName string
	MARS         byte
}

const MSSQL = "mssql"

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func DetectMSSQL(conn net.Conn, timeout time.Duration) (Data, bool, error) {
	// Below is a TDS prelogin packet sent by the client to begin the
	// initial handshake with the server
	preLoginPacket := []byte{

		// Pre-Login Request Header
		0x12,       // Type
		0x01,       // Status
		0x00, 0x58, // Length
		0x00, 0x00, // SPID
		0x01, // PacketID
		0x00, // Window

		// We configure the following options within the pre-login request body:
		//
		// VERSION:        11 09 00 01 00 00
		// ENCRYPTION:     00
		// INSTOPT:        00
		// THREADID:       00 00 00 00
		// MARS:           00
		// TRACEID:        f9 b8 cb 5c 94 6b 89 1f
		//                 d9 aa 3c 13 4b d0 7b 88
		//                 03 5c 32 21 24 a2 81 86
		//                 37 cf 62 39 4a 46 2c c6
		//                 00 00 00 00

		// Pre-Login Request Payload
		0x00,       // PLOptionToken (VERSION)
		0x00, 0x1F, // PLOffset
		0x00, 0x06, // PLOptionLength

		0x01,       // PLOptionToken (ENCRYPTION)
		0x00, 0x25, // PLOffset
		0x00, 0x01, // PLOptionLength

		0x02,       // PLOptionToken (INSTOPT)
		0x00, 0x26, // PLOffset
		0x00, 0x01, // PLOptionLength

		0x03,       // PLOptionToken (THREADID)
		0x00, 0x27, // PLOffset
		0x00, 0x04, // PLOptionLength

		0x04,       // PLOptionToken (MARS)
		0x00, 0x2B, // PLOffset
		0x00, 0x01, // PLOptionLength

		0x05,       // PLOptionToken (TRACEID)
		0x00, 0x2C, // PLOffset
		0x00, 0x24, // PLOptionLength

		0xFF, // TERMINATOR

		// PLOptionData
		0x11, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xF9, 0xB8, 0xCB,
		0x5C, 0x94, 0x6B, 0x89, 0x1F, 0xD9, 0xAA, 0x3C,
		0x13, 0x4B, 0xD0, 0x7B, 0x88, 0x03, 0x5C, 0x32,
		0x21, 0x24, 0xA2, 0x81, 0x86, 0x37, 0xCF, 0x62,
		0x39, 0x4A, 0x46, 0x2C, 0xC6, 0x00, 0x00, 0x00,
		0x00,
	}

	response, err := shared.SendRecv(conn, preLoginPacket, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &shared.ServerNotEnable{}
	}

	/*
		Below is an example pre-login response (tabular response) packet
		returned by the client to the server:

			Pre-Login Response (Tabular Response) Header:

			Type:     0x04
			Status:   0x01
			Length:   0x00 0x30
			SPID:     0x00 0x00
			PacketId: 0x01
			Window:   0x00

			Pre-Login Response Body:

			PLOptionToken:  0x00 (VERSION)
			PLOffset:        0x00 0x1F
			PLOptionLength: 0x00 0x06

			PLOptionToken:  0x01 (ENCRYPTION)
			PLOffset:        0x00 0x25
			PLOptionLength: 0x00 0x01

			PLOptionToken:  0x02 (INSTOPT)
			PLOffset:        0x00 0x26
			PLOptionLength: 0x00 0x01

			PLOptionToken:  0x03 (THREADID)
			PLOffset:        0x00 0x27
			PLOptionLength: 0x00 0x00

			PLOptionToken:  0x04 (MARS)
			PLOffset:        0x00 0x27
			PLOptionLength: 0x00 0x01

			PLOptionToken:  0x05 (TRACEID)
			PLOffset:        0x00 0x28
			PLOptionLength: 0x00 0x00

			PLOptionToken:  0xFF

			PLOptionData:   0f 00 07 d0 00 00 00 00 00

			VERSION:    0f 00 07 d0 00 00
			ENCRYPTION: 00
			INSTOPT     00
			MARS:       00
	*/

	// The TDS header is eight bytes so any response less than this can be safely classified
	// as invalid (i.e. not MSSQL/TDS)
	if len(response) < 8 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "response is too short to be a valid TDS packet header",
		}
	}

	if response[0] != 0x04 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "type should be set to tabular result for a valid TDS packet",
		}
	}

	if response[1] != 0x01 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "expect a status of one (end of message) for tabular result packet",
		}
	}

	packetLength := int(uint32(response[3]) | uint32(response[2])<<8)
	if len(response) != packetLength {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "packet length does not match length read",
		}
	}

	if response[4] != 0x00 || response[5] != 0x00 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for SPID should always be zero",
		}
	}

	if response[6] != 0x01 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for packet id should always be one",
		}
	}

	if response[7] != 0x00 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for window should always be zero",
		}
	}

	// The body of the pre-login response message is a list of PL_OPTION tokens
	// that index into the PLOptionData segment and the list is
	// terminated by a PLOptionToken with TERMINATOR (0xFF) as the value.

	position := 8 // set to the position to just after the TDS packet header

	var optionTokens []OptionToken
	for response[position] != TERMINATOR && position < len(response) {
		plOptionToken := uint32(response[position+0])
		plOffset := uint32(response[position+2]) | uint32(response[position+1])<<8
		plOptionLength := uint32(response[position+4]) | uint32(response[position+3])<<8

		plOptionData := []byte{}
		if plOptionLength != 0 {
			if plOffset+8+plOptionLength <= uint32(len(response)) {
				plOptionData = response[plOffset+8 : plOffset+8+plOptionLength]
			} else {
				return Data{}, true, &shared.InvalidResponseErrorInfo{
					Service: MSSQL,
					Info:    "server returned an invalid PLOffset or PLOptionLength"}
			}
		}

		position += 5
		optionTokenStruct := OptionToken{
			PLOptionToken:  plOptionToken,
			PLOffset:       plOffset,
			PLOptionLength: plOptionLength,
			PLOptionData:   plOptionData,
		}

		optionTokens = append(optionTokens, optionTokenStruct)
	}

	if response[position] != 0xFF {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "list of option tokens should be terminated by 0xff",
		}
	}

	if len(optionTokens) < 1 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "there should be at least one option token since VERSION is required",
		}
	}

	if optionTokens[0].PLOptionToken != 0x00 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "TDS requires VERSION to be the first PLOptionToken value",
		}
	}

	if optionTokens[0].PLOptionLength != 0x06 {
		return Data{}, true, &shared.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "version field should be fixed bytes",
		}
	}

	MajorVersion := optionTokens[0].PLOptionData[0]
	MinorVersion := optionTokens[0].PLOptionData[1]
	BuildNumber := uint32(
		(uint32(optionTokens[0].PLOptionData[2]) * 256) + uint32(
			optionTokens[0].PLOptionData[3],
		),
	)

	version := fmt.Sprintf("%d.%d.%d", MajorVersion, MinorVersion, BuildNumber)

	data := Data{Version: version}

	// Extract additional prelogin options (best-effort, failures silently skipped)
	for _, tok := range optionTokens {
		switch int(tok.PLOptionToken) {
		case ENCRYPTION:
			if len(tok.PLOptionData) >= 1 {
				data.Encryption = tok.PLOptionData[0]
			}
		case INSTOPT:
			if len(tok.PLOptionData) >= 1 {
				// Instance name is a null-terminated string
				name := string(tok.PLOptionData)
				name = strings.TrimRight(name, "\x00")
				if name != "" {
					data.InstanceName = name
				}
			}
		case MARS:
			if len(tok.PLOptionData) >= 1 {
				data.MARS = tok.PLOptionData[0]
			}
		}
	}

	return data, true, nil
}

// encryptionString maps the ENCRYPTION prelogin option byte to a human-readable string.
func encryptionString(b byte) string {
	switch b {
	case 0x00:
		return "off"
	case 0x01:
		return "on"
	case 0x02:
		return "not_supported"
	case 0x03:
		return "required"
	default:
		return fmt.Sprintf("unknown(0x%02x)", b)
	}
}

// marsString maps the MARS prelogin option byte to a human-readable string.
func marsString(b byte) string {
	switch b {
	case 0x00:
		return "off"
	case 0x01:
		return "on"
	default:
		return fmt.Sprintf("unknown(0x%02x)", b)
	}
}

// productName maps a major version number to a SQL Server product name.
func productName(version string) string {
	if len(version) == 0 {
		return ""
	}
	// Extract major version (everything before the first dot)
	major := version
	if idx := strings.Index(version, "."); idx != -1 {
		major = version[:idx]
	}
	switch major {
	case "16":
		return "SQL Server 2022"
	case "15":
		return "SQL Server 2019"
	case "14":
		return "SQL Server 2017"
	case "13":
		return "SQL Server 2016"
	case "12":
		return "SQL Server 2014"
	case "11":
		return "SQL Server 2012"
	case "10":
		return "SQL Server 2008"
	case "9":
		return "SQL Server 2005"
	case "8":
		return "SQL Server 2000"
	default:
		return ""
	}
}

// buildLogin7WithNTLM constructs a TDS Login7 packet containing an NTLM Type 1
// (Negotiate) message for SSPI authentication. This triggers the server to respond
// with an NTLM Type 2 (Challenge) message containing OS and domain metadata.
func buildLogin7WithNTLM() []byte {
	// NTLM Type 1 (Negotiate) message — requests NTLM and Unicode support
	ntlmNegotiate := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x01, 0x00, 0x00, 0x00, // MessageType: NtLmNegotiate
		0x97, 0x82, 0x08, 0xe2, // NegotiateFlags
		0x00, 0x00, // DomainNameLen
		0x00, 0x00, // DomainNameMaxLen
		0x00, 0x00, 0x00, 0x00, // DomainNameBufferOffset
		0x00, 0x00, // WorkstationLen
		0x00, 0x00, // WorkstationMaxLen
		0x00, 0x00, 0x00, 0x00, // WorkstationBufferOffset
		0x0a, 0x00, 0x63, 0x45, // Version (10.0.17859)
		0x00, 0x00, 0x00, 0x0f, // Revision
	}

	// Login7 fixed-length body is 94 bytes (36 bytes fixed header + 58 bytes of
	// offset/length pairs for client name, app name, server name, etc.)
	// All string fields are empty (offset points past fixed body, length=0).
	login7FixedLen := 94
	totalLogin7Len := login7FixedLen + len(ntlmNegotiate)

	login7 := make([]byte, login7FixedLen)
	// Length (includes itself): total Login7 payload length
	binary.LittleEndian.PutUint32(login7[0:4], uint32(totalLogin7Len))
	// TDSVersion: 7.4 (SQL Server 2012+)
	binary.LittleEndian.PutUint32(login7[4:8], 0x74000004)
	// PacketSize
	binary.LittleEndian.PutUint32(login7[8:12], 4096)
	// ClientProgVer, ClientPID, ConnectionID: all zero (bytes 12-23)
	// OptionFlags1 (byte 24): 0x00
	// OptionFlags2 (byte 25): 0x80 = fIntSecurity (SSPI authentication)
	login7[25] = 0x80
	// TypeFlags (byte 26), OptionFlags3 (byte 27): 0x00
	// ClientTimeZone (bytes 28-31): 0x00000000
	// ClientLCID (bytes 32-35): 0x00000000

	// Offset/length pairs for variable-length fields start at byte 36.
	// All string fields are empty — they all point to the same offset (end of fixed body)
	// with length 0. The SSPI field points to the NTLM message.
	emptyOffset := uint16(login7FixedLen)

	// ibHostName, cchHostName (bytes 36-39)
	binary.LittleEndian.PutUint16(login7[36:38], emptyOffset)
	// ibUserName, cchUserName (bytes 40-43)
	binary.LittleEndian.PutUint16(login7[40:42], emptyOffset)
	// ibPassword, cchPassword (bytes 44-47)
	binary.LittleEndian.PutUint16(login7[44:46], emptyOffset)
	// ibAppName, cchAppName (bytes 48-51)
	binary.LittleEndian.PutUint16(login7[48:50], emptyOffset)
	// ibServerName, cchServerName (bytes 52-55)
	binary.LittleEndian.PutUint16(login7[52:54], emptyOffset)
	// ibUnused, cbUnused (bytes 56-59): reserved
	binary.LittleEndian.PutUint16(login7[56:58], emptyOffset)
	// ibCltIntName, cchCltIntName (bytes 60-63)
	binary.LittleEndian.PutUint16(login7[60:62], emptyOffset)
	// ibLanguage, cchLanguage (bytes 64-67)
	binary.LittleEndian.PutUint16(login7[64:66], emptyOffset)
	// ibDatabase, cchDatabase (bytes 68-71)
	binary.LittleEndian.PutUint16(login7[68:70], emptyOffset)
	// ClientID (bytes 72-77): 6 bytes, all zero
	// ibSSPI, cbSSPI (bytes 78-81)
	binary.LittleEndian.PutUint16(login7[78:80], emptyOffset)
	binary.LittleEndian.PutUint16(login7[80:82], uint16(len(ntlmNegotiate)))
	// ibAtchDBFile, cchAtchDBFile (bytes 82-85)
	binary.LittleEndian.PutUint16(login7[82:84], emptyOffset)
	// ibChangePassword, cchChangePassword (bytes 86-89)
	binary.LittleEndian.PutUint16(login7[86:88], emptyOffset)
	// cbSSPILong (bytes 90-93): 0 (only used when cbSSPI=0xFFFF)

	// Append NTLM negotiate message
	login7 = append(login7, ntlmNegotiate...)

	// Wrap in TDS packet header (type 0x10 = Login7)
	tdsHeader := make([]byte, 8)
	tdsHeader[0] = 0x10 // Type: Login7
	tdsHeader[1] = 0x01 // Status: EOM
	totalLen := uint16(8 + len(login7))
	binary.BigEndian.PutUint16(tdsHeader[2:4], totalLen)
	// SPID (bytes 4-5): 0x0000
	tdsHeader[6] = 0x01 // PacketID
	// Window (byte 7): 0x00

	return append(tdsHeader, login7...)
}

// probeNTLM sends a TDS Login7 packet with NTLM Type 1 negotiate and parses
// the server's NTLM Type 2 challenge response for OS and domain metadata.
func probeNTLM(conn net.Conn, timeout time.Duration) (*ntlm.TargetInfo, error) {
	packet := buildLogin7WithNTLM()
	response, err := shared.SendRecv(conn, packet, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, fmt.Errorf("empty response to NTLM probe")
	}
	return ntlm.ParseChallenge(response)
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, check, err := DetectMSSQL(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if !check && err != nil {
		return nil, err
	}

	service := ServiceMSSQL{
		Version:     data.Version,
		ProductName: productName(data.Version),
		Encryption:  encryptionString(data.Encryption),
		MARS:        marsString(data.MARS),
	}
	if data.InstanceName != "" {
		service.InstanceName = data.InstanceName
	}

	// Attempt NTLM probe for OS/domain metadata.
	// Only when: connection is already TLS, or encryption is OFF (0x00) or NOT_SUPPORTED (0x02).
	// When encryption is ON (0x01) or REQUIRED (0x03) on a non-TLS connection,
	// TDS-level TLS negotiation would be needed, which we don't implement.
	canProbe := conn.TLS() != nil || data.Encryption == 0x00 || data.Encryption == 0x02
	if canProbe {
		info, ntlmErr := probeNTLM(conn, timeout)
		if ntlmErr == nil && info != nil {
			service.OSVersion = info.OSVersion
			service.NetBIOSComputerName = info.NetBIOSComputerName
			service.NetBIOSDomainName = info.NetBIOSDomainName
			service.DNSComputerName = info.DNSComputerName
			service.DNSDomainName = info.DNSDomainName
			service.ForestName = info.ForestName
		}
	}

	return plugins.CreateServiceFrom(target, p.Name(), service, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return MSSQL
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 143
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{1433}
}
