package mongodb

// ServiceMongoDB holds metadata for a detected MongoDB service.
type ServiceMongoDB struct {
	CPEs           []string `json:"cpes,omitempty"`
	MaxWireVersion int      `json:"maxWireVersion,omitempty"`
	MinWireVersion int      `json:"minWireVersion,omitempty"`
	ServerType     string   `json:"serverType,omitempty"`
}
