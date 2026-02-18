package postgres

type ServicePostgreSQL struct {
	AuthRequired    bool     `json:"authRequired,omitempty"`
	AuthMethod      string   `json:"authMethod,omitempty"`
	SASLMechanisms  []string `json:"saslMechanisms,omitempty"`
	ErrorSeverity   string   `json:"errorSeverity,omitempty"`
	ErrorCode       string   `json:"errorCode,omitempty"`
	ErrorMessage    string   `json:"errorMessage,omitempty"`
	ServerVersion   string   `json:"serverVersion,omitempty"`
	ServerEncoding  string   `json:"serverEncoding,omitempty"`
	TimeZone        string   `json:"timeZone,omitempty"`
	ProtocolVersion string   `json:"protocolVersion,omitempty"`
	SSLSupported    bool     `json:"sslSupported,omitempty"`
}
