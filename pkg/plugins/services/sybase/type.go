package sybase

// ServiceSybase holds metadata for a detected Sybase ASE service.
type ServiceSybase struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
}
