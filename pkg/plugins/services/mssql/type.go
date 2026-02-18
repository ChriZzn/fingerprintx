package mssql

type ServiceMSSQL struct {
	Version             string `json:"version,omitempty"`
	ProductName         string `json:"productName,omitempty"`
	Encryption          string `json:"encryption,omitempty"`
	InstanceName        string `json:"instanceName,omitempty"`
	MARS                string `json:"mars,omitempty"`
	OSVersion           string `json:"osVersion,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}
