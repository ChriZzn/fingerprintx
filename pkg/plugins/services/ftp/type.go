package ftp

type ServiceFTP struct {
	Banner    string `json:"banner,omitempty"`
	Anonymous bool   `json:"anonymous,omitempty"`
	Data      string `json:"data,omitempty"`
}
