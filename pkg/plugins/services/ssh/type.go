package ssh

type ServiceSSH struct {
	Banner              string `json:"banner,omitempty"`
	PasswordAuthEnabled bool   `json:"passwordAuthEnabled,omitempty"`
	Algo                string `json:"algo,omitempty"`
	HostKey             string `json:"hostKey,omitempty"`
	HostKeyType         string `json:"hostKeyType,omitempty"`
	HostKeyFingerprint  string `json:"hostKeyFingerprint,omitempty"`
}
