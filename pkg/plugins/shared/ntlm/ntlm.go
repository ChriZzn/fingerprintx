package ntlm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Constants for NTLM message types
const (
	NTLMNegotiate    uint32 = 0x00000001
	NTLMChallenge    uint32 = 0x00000002
	NTLMAuthenticate uint32 = 0x00000003
)

// Challenge represents the NTLM challenge message structure
type Challenge struct {
	Signature              [8]byte
	MessageType            uint32
	TargetNameLen          uint16
	TargetNameMaxLen       uint16
	TargetNameBufferOffset uint32
	NegotiateFlags         uint32
	ServerChallenge        uint64
	Reserved               uint64
	TargetInfoLen          uint16
	TargetInfoMaxLen       uint16
	TargetInfoBufferOffset uint32
	Version                [8]byte
}

// OSVersion represents Windows version information
type OSVersion struct {
	MajorVersion byte
	MinorVersion byte
	BuildNumber  uint16
}

// AVPair represents an attribute-value pair in NTLM messages
type AVPair struct {
	AvID  uint16
	AvLen uint16
}

// TargetInfo contains the parsed target information from NTLM messages
type TargetInfo struct {
	OSVersion           string
	TargetName          string
	NetBIOSComputerName string
	NetBIOSDomainName   string
	DNSComputerName     string
	DNSDomainName       string
	ForestName          string
}

// ParseChallenge parses an NTLM challenge message and extracts target information
func ParseChallenge(response []byte) (*TargetInfo, error) {
	info := &TargetInfo{}
	challengeLen := 56

	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		return nil, fmt.Errorf("NTLM signature not found")
	}

	if len(response) < challengeStartOffset+challengeLen {
		return nil, fmt.Errorf("Response too short")
	}

	var challengeData Challenge
	response = response[challengeStartOffset:]
	responseBuf := bytes.NewBuffer(response)
	if err := binary.Read(responseBuf, binary.LittleEndian, &challengeData); err != nil {
		return nil, err
	}

	// Validate NTLM challenge message structure
	if challengeData.MessageType != NTLMChallenge ||
		challengeData.Reserved != 0 ||
		!bytes.Equal(challengeData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return nil, fmt.Errorf("Invalid NTLM challenge structure")
	}

	// Parse version information
	var version OSVersion
	versionBuf := bytes.NewBuffer(challengeData.Version[:4])
	if err := binary.Read(versionBuf, binary.LittleEndian, &version); err != nil {
		return nil, err
	}
	info.OSVersion = fmt.Sprintf("%d.%d.%d", version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber)

	// Parse target name if present
	targetNameLen := int(challengeData.TargetNameLen)
	if targetNameLen > 0 {
		startIdx := int(challengeData.TargetNameBufferOffset)
		endIdx := startIdx + targetNameLen
		if endIdx <= len(response) {
			info.TargetName = strings.ReplaceAll(string(response[startIdx:endIdx]), "\x00", "")
		}
	}

	// Parse target info
	return parseTargetInfo(response, challengeData, info)
}

func parseTargetInfo(response []byte, challengeData Challenge, info *TargetInfo) (*TargetInfo, error) {
	avIDMap := map[uint16]string{
		1: "NetBIOSComputerName",
		2: "NetBIOSDomainName",
		3: "DNSComputerName",
		4: "DNSDomainName",
		5: "DNSTreeName",
	}

	targetInfoLen := int(challengeData.TargetInfoLen)
	if targetInfoLen <= 0 {
		return info, nil
	}

	startIdx := int(challengeData.TargetInfoBufferOffset)
	if startIdx+targetInfoLen > len(response) {
		return info, fmt.Errorf("Invalid TargetInfoLen value")
	}

	currIdx := startIdx
	for currIdx+4 <= startIdx+targetInfoLen {
		var avPair AVPair
		avPairBuf := bytes.NewBuffer(response[currIdx : currIdx+4])
		if err := binary.Read(avPairBuf, binary.LittleEndian, &avPair); err != nil {
			return info, nil
		}

		if avPair.AvID == 0 {
			break
		}

		if field, exists := avIDMap[avPair.AvID]; exists {
			valueEnd := currIdx + 4 + int(avPair.AvLen)
			if valueEnd > len(response) {
				return info, fmt.Errorf("Invalid AV_PAIR length")
			}
			value := strings.ReplaceAll(string(response[currIdx+4:valueEnd]), "\x00", "")

			switch field {
			case "NetBIOSComputerName":
				info.NetBIOSComputerName = value
			case "NetBIOSDomainName":
				info.NetBIOSDomainName = value
			case "DNSComputerName":
				info.DNSComputerName = value
			case "DNSDomainName":
				info.DNSDomainName = value
			case "DNSTreeName":
				info.ForestName = value
			}
		}

		currIdx += 4 + int(avPair.AvLen)
	}

	return info, nil
}
