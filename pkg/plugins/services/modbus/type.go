package modbus

type ServiceModbus struct {
	// Device Identification (FC 0x2B, MEI type 0x0E)
	VendorName          string `json:"vendorName,omitempty"`
	ProductCode         string `json:"productCode,omitempty"`
	MajorMinorRevision  string `json:"majorMinorRevision,omitempty"`
	VendorURL           string `json:"vendorUrl,omitempty"`
	ProductName         string `json:"productName,omitempty"`
	ModelName           string `json:"modelName,omitempty"`
	UserApplicationName string `json:"userApplicationName,omitempty"`
	ConformityLevel     int    `json:"conformityLevel,omitempty"`

	// Report Server ID (FC 0x11)
	ServerID     string `json:"serverId,omitempty"`
	RunIndicator string `json:"runIndicator,omitempty"`
	ServerInfo   string `json:"serverInfo,omitempty"`
}
