package mysql

type ServiceMySQL struct {
	PacketType   string `json:"packetType,omitempty"` // the type of packet returned by the server (i.e. handshake or error)
	ErrorMessage string `json:"errorMsg,omitempty"`   // error message if the server returns an error packet
	ErrorCode    int    `json:"errorCode,omitempty"`  // error code returned if the server returns an error packet
	Version      string `json:"version,omitempty"`
}
