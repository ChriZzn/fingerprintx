package snmp

type ServiceSNMP struct {
	Version     int    `json:"version,omitempty"`
	SysDescr    string `json:"sysDescr,omitempty"`    // 1.3.6.1.2.1.1.1.0
	SysObjectID string `json:"sysObjectID,omitempty"` // 1.3.6.1.2.1.1.2.0
	SysName     string `json:"sysName,omitempty"`     // 1.3.6.1.2.1.1.5.0
	SysLocation string `json:"sysLocation,omitempty"` // 1.3.6.1.2.1.1.6.0
	SysContact  string `json:"sysContact,omitempty"`  // 1.3.6.1.2.1.1.4.0
	EngineID    string `json:"engineID,omitempty"`    // v3: hex-encoded
	EngineBoots int    `json:"engineBoots,omitempty"` // v3
	EngineTime  int    `json:"engineTime,omitempty"`  // v3
}
