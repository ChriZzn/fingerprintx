package neo4j

// ServiceNeo4j holds metadata for a detected Neo4j service.
type ServiceNeo4j struct {
	CPEs []string `json:"cpes,omitempty"`
}
