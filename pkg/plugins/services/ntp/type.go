package ntp

type ServiceNTP struct {
	ProtocolVersion uint8   `json:"protocol_version,omitempty"`
	Stratum         uint8   `json:"stratum,omitempty"`
	Leap            uint8   `json:"leap,omitempty"`
	Precision       int8    `json:"precision,omitempty"`
	RootDelay       float64 `json:"root_delay,omitempty"`
	RootDispersion  float64 `json:"root_dispersion,omitempty"`
	RefID           uint32  `json:"ref_id,omitempty"`
	RefTime         float64 `json:"ref_time,omitempty"`
	Poll            uint8   `json:"poll,omitempty"`
}
