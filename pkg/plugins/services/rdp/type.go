package rdp

type ServiceRDP struct {
	OSFingerprint       string `json:"fingerprint,omitempty"`      // e.g. Windows Server 2016 or 2019
	OSVersion           string `json:"osVersion,omitempty"`        // e.g. 10.0.17763
	SecurityProtocol    string `json:"securityProtocol,omitempty"` // e.g. Standard RDP, TLS, CredSSP
	NLARequired         bool   `json:"nlaRequired,omitempty"`      // true when CredSSP/NLA is required
	TargetName          string `json:"targetName,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}
