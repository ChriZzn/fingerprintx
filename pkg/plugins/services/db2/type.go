package db2

type ServiceDB2 struct {
	ServerName string   `json:"serverName,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}
