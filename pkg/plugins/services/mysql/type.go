package mysql

type ServiceMySQL struct {
	PacketType   string `json:"packetType"` // the type of packet returned by the server (i.e. handshake or error)
	ErrorMessage string `json:"errorMsg"`   // error message if the server returns an error packet
	ErrorCode    int    `json:"errorCode"`  // error code returned if the server returns an error packet
}
