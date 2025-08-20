package dns

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"net"
	"time"
)

type TCPPlugin struct{}

func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := ServiceDNS{}

		return plugins.CreateServiceFrom(target, p.Name(), payload, nil), nil
	}

	return nil, nil
}

func (p *TCPPlugin) Name() string {
	return DNS
}

func (p *TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TCPPlugin) Priority() int {
	return 50
}

func (p *TCPPlugin) Ports() []uint16 {
	return []uint16{53}
}
