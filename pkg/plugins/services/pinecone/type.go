package pinecone

// ServicePinecone holds metadata for a detected Pinecone service.
type ServicePinecone struct {
	CPEs       []string `json:"cpes,omitempty"`
	APIVersion string   `json:"apiVersion,omitempty"`
}
