package smb

type ServiceSMB struct {
	SigningEnabled  bool `json:"signingEnabled"`  // e.g. Is SMB Signing Enabled?
	SigningRequired bool `json:"signingRequired"` // e.g. Is SMB Signing Required?

	DialectRevision string   `json:"dialectRevision,omitempty"` // e.g. "3.0.2", "2.1"
	ServerGUID      string   `json:"serverGuid,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	MaxTransactSize uint32   `json:"maxTransactSize,omitempty"`
	MaxReadSize     uint32   `json:"maxReadSize,omitempty"`
	MaxWriteSize    uint32   `json:"maxWriteSize,omitempty"`
	SystemTime      string   `json:"systemTime,omitempty"`      // RFC 3339
	ServerStartTime string   `json:"serverStartTime,omitempty"` // RFC 3339

	OSVersion           string `json:"osVersion,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
	NTLMTimestamp       string `json:"ntlmTimestamp,omitempty"` // RFC 3339
}
