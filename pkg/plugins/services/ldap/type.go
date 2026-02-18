package ldap

type ServiceLDAP struct {
	// Connection info
	StartTLSSupported bool `json:"startTLSSupported,omitempty"`

	// Standard RootDSE attributes (RFC 4512)
	NamingContexts        []string `json:"namingContexts,omitempty"`
	SubschemaSubentry     string   `json:"subschemaSubentry,omitempty"`
	SupportedLDAPVersions []string `json:"supportedLDAPVersions,omitempty"`
	SupportedSASLMechs    []string `json:"supportedSASLMechanisms,omitempty"`
	SupportedExtensions   []string `json:"supportedExtensions,omitempty"`
	SupportedControls     []string `json:"supportedControls,omitempty"`
	VendorName            string   `json:"vendorName,omitempty"`
	VendorVersion         string   `json:"vendorVersion,omitempty"`

	// Active Directory specific
	DNSHostName                   string `json:"dnsHostName,omitempty"`
	DefaultNamingContext          string `json:"defaultNamingContext,omitempty"`
	DomainFunctionality           string `json:"domainFunctionality,omitempty"`
	ForestFunctionality           string `json:"forestFunctionality,omitempty"`
	DomainControllerFunctionality string `json:"domainControllerFunctionality,omitempty"`
	ServerName                    string `json:"serverName,omitempty"`
	IsGlobalCatalogReady          string `json:"isGlobalCatalogReady,omitempty"`
}
