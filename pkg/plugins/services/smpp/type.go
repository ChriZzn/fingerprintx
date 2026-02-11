package smpp

// ServiceSMPP holds metadata for a detected SMPP service.
type ServiceSMPP struct {
	CPEs            []string `json:"cpes,omitempty"`
	ProtocolVersion string   `json:"protocolVersion,omitempty"`
	SystemID        string   `json:"systemId,omitempty"`
	Vendor          string   `json:"vendor,omitempty"`
	Product         string   `json:"product,omitempty"`
}
