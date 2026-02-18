package ssh

type SSHAlgorithms struct {
	KexAlgorithms             []string `json:"kexAlgorithms,omitempty"`
	ServerHostKeyAlgorithms   []string `json:"serverHostKeyAlgorithms,omitempty"`
	CiphersClientToServer     []string `json:"ciphersClientToServer,omitempty"`
	CiphersServerToClient     []string `json:"ciphersServerToClient,omitempty"`
	MACsClientToServer        []string `json:"macsClientToServer,omitempty"`
	MACsServerToClient        []string `json:"macsServerToClient,omitempty"`
	CompressionClientToServer []string `json:"compressionClientToServer,omitempty"`
	CompressionServerToClient []string `json:"compressionServerToClient,omitempty"`
}

type ServiceSSH struct {
	Banner          string `json:"banner,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
	SoftwareVersion string `json:"softwareVersion,omitempty"`
	Comments        string `json:"comments,omitempty"`

	Algorithms *SSHAlgorithms `json:"algorithms,omitempty"`

	AuthMethods         []string `json:"authMethods,omitempty"`
	PasswordAuthEnabled bool     `json:"passwordAuthEnabled,omitempty"`

	HostKey            string `json:"hostKey,omitempty"`
	HostKeyType        string `json:"hostKeyType,omitempty"`
	HostKeyFingerprint string `json:"hostKeyFingerprint,omitempty"`
}
