package dns

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"time"
)

type UDPPlugin struct{}

func (p *UDPPlugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := ServiceDNS{}
		return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
	}

	return nil, nil
}

func (p *UDPPlugin) Name() string {
	return DNS
}

func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *UDPPlugin) Priority() int {
	return 50
}

func (p *UDPPlugin) Ports() []uint16 {
	return []uint16{53}
}
