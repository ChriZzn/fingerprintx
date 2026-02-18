package mysql

type ServiceMySQL struct {
	PacketType      string   `json:"packetType,omitempty"`
	ServerType      string   `json:"serverType,omitempty"`
	Version         string   `json:"version,omitempty"`
	ProtocolVersion int      `json:"protocolVersion,omitempty"`
	ConnectionID    uint32   `json:"connectionId,omitempty"`
	CharacterSet    string   `json:"characterSet,omitempty"`
	StatusFlags     uint16   `json:"statusFlags,omitempty"`
	CapabilityFlags uint32   `json:"capabilityFlags,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	AuthPluginName  string   `json:"authPluginName,omitempty"`
	ErrorMessage    string   `json:"errorMsg,omitempty"`
	ErrorCode       int      `json:"errorCode,omitempty"`
	ErrorSQLState   string   `json:"errorSQLState,omitempty"`
}
