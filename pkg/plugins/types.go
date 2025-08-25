// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugins

import (
	"crypto/tls"
	"encoding/json"
	"github.com/ChriZzn/sslx/sslx"
	"log"
	"net"
	"net/netip"
	"time"
)

// Protocol type SupportedIPVersion uint64
type Protocol uint64

const (
	IP Protocol = iota + 1
	UDP
	TCP
)

type PluginID struct {
	name     string
	protocol Protocol
	priority int
}

type Plugin interface {
	Run(*FingerprintConn, time.Duration, Target) (*Service, error)
	Name() string
	Type() Protocol
	Priority() int
	Ports() []uint16
}

// CreateServiceFrom initializes and returns a new Service object based on the provided Target, metadata, SSL, and transport.
// The Service object includes host, IP, port, protocol, transport layer, SSL settings, and raw JSON metadata.
func CreateServiceFrom(target Target, protocol string, metadata any, ssl *tls.ConnectionState) *Service {
	service := Service{
		Host:      target.Host,
		IP:        target.Address.Addr().String(),
		Port:      int(target.Address.Port()),
		Transport: target.Transport.String(),
		Protocol:  protocol,
	}

	// SSL Fingerprinting
	if ssl != nil {
		sslInfo, sslErr := sslx.GatherSSLInfo(ssl)
		if sslInfo != nil && sslErr == nil {
			service.SSL = sslInfo
		} else {
			log.Printf("Failed to gather SSL info: %v", sslErr)
		}
	}

	// Service Metadata
	if metadata != nil {
		j, mErr := json.Marshal(metadata)
		if j != nil && mErr == nil {
			service.Metadata = j
		} else {
			log.Printf("Failed to marshal metadata: %v", mErr)
		}
	}

	return &service
}

type Service struct {
	Host     string `json:"host,omitempty"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`

	Transport string          `json:"transport"`
	SSL       *sslx.SSLInfo   `json:"ssl,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// Target represents a network connection target that includes an address, host, and transport protocol.
type Target struct {
	Address   netip.AddrPort
	Host      string
	Transport Protocol
}

func (t Target) String() string {
	return t.Address.String() + "/" + t.Transport.String()
}

// Connection Struct

type FingerprintConn struct {
	net.Conn
}

func (c *FingerprintConn) TLS() *tls.ConnectionState {
	if tlsConn, ok := c.Conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		return &state
	}
	return nil
}

func (c *FingerprintConn) Upgrade() {

	conn := c.Conn.(*net.TCPConn)

	t := tls.Client(conn, &tlsConfig)
	err := t.Handshake()
	if err == nil {
		c.Conn = t
	}
}
