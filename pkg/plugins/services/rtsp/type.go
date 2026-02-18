package rtsp

type Track struct {
	Type      string `json:"type,omitempty"`
	Codec     string `json:"codec,omitempty"`
	ClockRate string `json:"clockRate,omitempty"`
}

type ServiceRtsp struct {
	StatusCode   int      `json:"statusCode,omitempty"`
	StatusReason string   `json:"statusReason,omitempty"`
	ServerInfo   string   `json:"serverInfo,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	AuthRequired bool     `json:"authRequired,omitempty"`
	AuthType     string   `json:"authType,omitempty"`
	StreamName   string   `json:"streamName,omitempty"`
	StreamInfo   string   `json:"streamInfo,omitempty"`
	Tracks       []Track  `json:"tracks,omitempty"`
}
