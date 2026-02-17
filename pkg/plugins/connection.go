package plugins

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

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

func Connect(ctx context.Context, target Target, dialTimeout time.Duration) (*FingerprintConn, error) {
	conn, err := connectTLS(ctx, target, dialTimeout)
	if err == nil {
		return &FingerprintConn{Conn: conn}, nil
	}

	conn, err = connectRAW(ctx, target, dialTimeout)
	if err == nil {
		return &FingerprintConn{Conn: conn}, nil
	}
	return nil, err
}

func connectRAW(ctx context.Context, target Target, dialTimeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}

	return dialer.DialContext(ctx, target.Transport.String(), target.String())
}

func connectTLS(ctx context.Context, target Target, dialTimeout time.Duration) (net.Conn, error) {
	config := &tlsConfig

	if target.Host != "" {
		c := config.Clone()
		c.ServerName = target.Host
		config = c
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    config,
	}
	return d.DialContext(ctx, target.Transport.String(), target.String())
}
