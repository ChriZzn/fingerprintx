package jdwp

type ServiceJDWP struct {
	Description string `json:"description,omitempty"`
	JdwpMajor   int32  `json:"jdwpMajor,omitempty"`
	JdwpMinor   int32  `json:"jdwpMinor,omitempty"`
	VMVersion   string `json:"VMVersion,omitempty"`
	VMName      string `json:"VMName,omitempty"`
}
