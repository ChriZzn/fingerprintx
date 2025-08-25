package http

type ServiceHTTP struct {
	Server       string   `json:"server,omitempty"`
	Status       int      `json:"status,omitempty"`
	Title        string   `json:"title,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	CPEs         []string `json:"cpes,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	Favicon      Favicon  `json:"favicon,omitempty"`
	Headers      []Header `json:"headers,omitempty"`
}

type Favicon struct {
	Hash int32  `json:"hash,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
