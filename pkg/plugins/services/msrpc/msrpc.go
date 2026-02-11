package msrpc

import (
	"encoding/binary"
	"fmt"
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"time"
)

type Plugin struct{}

const (
	MSRPC = "msrpc"
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// MSRPC packet constants
const (
	// Version 5.0
	RPC_VERSION       = 5
	RPC_MINOR_VERSION = 0

	// Packet types
	PKT_BIND_ACK = 0x0C
	PKT_BIND_NAK = 0x0D

	NDR_LOCAL_DATA_REP = 0x10

	PacketType  = 0    // Request
	PacketFlags = 3    // First + Last fragment
	DataRep     = 0x10 // Little-endian
	FragLength  = 74
	AuthLength  = 0
	CallID      = 1
)

func createBindRequest() []byte {
	request := make([]byte, FragLength)

	request[0] = RPC_VERSION
	request[1] = RPC_MINOR_VERSION
	request[2] = PacketType
	request[3] = PacketFlags
	binary.LittleEndian.PutUint32(request[4:8], DataRep)
	binary.LittleEndian.PutUint16(request[8:10], FragLength)
	binary.LittleEndian.PutUint16(request[10:12], AuthLength)
	binary.LittleEndian.PutUint32(request[12:16], CallID)

	return request
}

func isValidMSRPCResponse(response []byte) bool {

	// Need at least 5 bytes to validate version, packet type, and data representation
	if len(response) < 5 {
		return false
	}

	// Check version (5.0)
	if response[0] != RPC_VERSION || response[1] != RPC_MINOR_VERSION {
		return false
	}

	// Check packet type (should be BIND_ACK or BIND_NAK)
	ptype := response[2]
	if ptype != PKT_BIND_ACK && ptype != PKT_BIND_NAK {
		return false
	}

	// Check data representation (should be little-endian)
	dataRep := response[4]
	if dataRep != NDR_LOCAL_DATA_REP {
		return false
	}

	return true
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {

	// Set deadline for the connection
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %v", err)
	}

	// Send the bind request
	bindRequest := createBindRequest()
	resp, err := shared.SendRecvAll(conn, bindRequest, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to send bind request: %v", err)
	}

	if !isValidMSRPCResponse(resp) {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, p.Name(), nil, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return MSRPC
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 130
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{135}
}
