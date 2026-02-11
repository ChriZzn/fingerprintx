package cassandra

type ServiceCassandra struct {
	Product          string   `json:"product,omitempty"`
	CQLVersion       string   `json:"cqlVersion,omitempty"`
	ProtocolVersions []string `json:"protocolVersions,omitempty"`
	Compression      []string `json:"compression,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	CPEs             []string `json:"cpes,omitempty"`
}
