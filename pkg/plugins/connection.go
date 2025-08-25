package plugins

import (
	"crypto/tls"
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

func Connect(target Target) (*FingerprintConn, error) {
	conn, err := connectTLS(target)
	if err == nil {
		return &FingerprintConn{Conn: conn}, nil
	}

	conn, err = connectRAW(target)
	if err == nil {
		return &FingerprintConn{Conn: conn}, nil
	}
	return nil, err
}

func connectRAW(target Target) (net.Conn, error) {
	return dialer.Dial(target.Transport.String(), target.Address.String())
}

func connectTLS(target Target) (net.Conn, error) {
	config := &tlsConfig

	if target.Host != "" {
		c := config.Clone()
		c.ServerName = target.Host
		config = c
	}
	return tls.DialWithDialer(dialer, target.Transport.String(), target.Address.String(), config)
}
