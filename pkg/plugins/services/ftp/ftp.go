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

package ftp

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"regexp"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

var ftpResponse = regexp.MustCompile(`^\d{3}[- ](.*)\r`)

const FTP = "ftp"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {

	// Initial banner read
	response, err := shared.Recv(conn, timeout)
	if len(response) == 0 || err != nil {
		return nil, nil
	}

	// FTP banners must start with a 3-digit status code (e.g. "220 Welcome")
	if !ftpResponse.Match(response) {
		return nil, nil
	}

	b := strings.Split(string(response), "\r\n")
	trace := string(response)

	// HELP
	helpCMD := []byte("HELP\r\n")
	response, err = shared.SendRecvAll(conn, helpCMD, timeout)
	trace += string(response)

	payload := ServiceFTP{
		Anonymous: false,
		Banner:    strings.TrimSpace(b[0]),
	}

	// Try anonymous login
	userCMD := []byte("USER anonymous\r\n")
	response, err = shared.SendRecvAll(conn, userCMD, timeout)
	trace += string(response)
	pwdCMD := []byte("PASS anonymous@example.com\r\n")
	response, err = shared.SendRecvAll(conn, pwdCMD, timeout)
	trace += string(response)
	// check response
	if regexp.MustCompile(`^230`).Match(response) {
		payload.Anonymous = true
	}

	// append trace
	payload.Data = trace

	// StartTLS
	startTlsCMD := []byte("AUTH TLS\r\n")
	response, err = shared.SendRecvAll(conn, startTlsCMD, timeout)
	conn.Upgrade()

	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return FTP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 10
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{21}
}
