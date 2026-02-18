package redis

type ServiceRedis struct {
	AuthRequired  bool   `json:"authRequired,omitempty"`
	ProtectedMode bool   `json:"protectedMode,omitempty"`
	Version       string `json:"version,omitempty"`
	RedisMode     string `json:"redisMode,omitempty"`
	OS            string `json:"os,omitempty"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
}
