package scan

import (
	"crypto/tls"
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"net"
	"time"
)

var dialer = &net.Dialer{
	Timeout: 2 * time.Second,
}
var tlsConfig = tls.Config{} //nolint:gosec

func init() {
	cipherSuites := make([]uint16, 0)
	for _, suite := range tls.CipherSuites() {
		cipherSuites = append(cipherSuites, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		cipherSuites = append(cipherSuites, suite.ID)
	}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.CipherSuites = cipherSuites
	tlsConfig.MinVersion = tls.VersionSSL30
}

func Connect(target plugins.Target) (net.Conn, error) {
	conn, err := connectTLS(target)
	if err == nil {
		return conn, nil
	}
	return connectRAW(target)
}

func connectRAW(target plugins.Target) (net.Conn, error) {
	return dialer.Dial(target.Transport.String(), target.Address.String())
}

func connectTLS(target plugins.Target) (net.Conn, error) {
	config := &tlsConfig
	if target.Host != "" {
		c := config.Clone()
		c.ServerName = target.Host
		config = c
	}
	return tls.DialWithDialer(dialer, "tcp", target.Address.String(), config)
}
