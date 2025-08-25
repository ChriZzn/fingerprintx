package linuxrpc

type ServiceRPC struct {
	Entries []RPCB `json:"entries,omitempty"`
}

type RPCB struct {
	Program  int    `json:"program,omitempty"`
	Version  int    `json:"version,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Address  string `json:"address,omitempty"`
	Owner    string `json:"owner,omitempty"`
}
