package stun

type ServiceStun struct {
	Attributes []Attribute `json:"attributes,omitempty"`
}

type Attribute struct {
	Key   string
	Value string
}
