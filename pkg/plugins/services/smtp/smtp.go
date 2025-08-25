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

package smtp

import (
	"bytes"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"net"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

type Plugin struct{}

const SMTP = "smtp"

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func handleSMTPConn(response []byte) (bool, bool) {
	// Checks for an expected response on CONNECTION ESTABLISHMENT
	// RFC 5321 Section 4.3.2
	validResponses := []string{"220", "421", "500", "501", "554"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {
			// Received a valid response code on connection
			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {
				// Received a valid error response code on connection
				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}

func handleSMTPHelo(response []byte) (bool, bool) {
	// Checks for an expected response from the HELO command
	// RFC 5321 Section 4.3.2
	validResponses := []string{"250", "421", "500", "501", "502", "504", "550"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {
			// HELO command received a valid response code
			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {
				// HELO command received a valid error response code
				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}

func DetectSMTP(conn net.Conn, timeout time.Duration) (ServiceSMTP, bool, error) {
	response, err := shared.RecvAll(conn, timeout)
	if err != nil {
		return ServiceSMTP{}, false, err
	}
	if len(response) == 0 {
		return ServiceSMTP{}, true, &shared.ServerNotEnable{}
	}

	isSMTP, smtpError := handleSMTPConn(response)
	if !isSMTP && !smtpError {
		return ServiceSMTP{}, true, &shared.InvalidResponseError{Service: SMTP}
	}

	banner := make([]byte, len(response))
	copy(banner, response)

	// Send the EHLO message
	response, err = shared.SendRecv(conn, []byte("EHLO example.com\r\n"), timeout)
	if err != nil {
		return ServiceSMTP{}, false, err
	}
	if len(response) == 0 {
		return ServiceSMTP{}, true, &shared.ServerNotEnable{}
	}

	isSMTP, smtpError = handleSMTPHelo(response)
	if !isSMTP {
		return ServiceSMTP{}, true, &shared.InvalidResponseErrorInfo{
			Service: SMTP,
			Info:    "invalid SMTP Helo response",
		}
	}

	data := ServiceSMTP{
		Banner: string(banner),
	}

	// Both smtpError and isSMTP indicate valid SMTP server
	return data, true, nil
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {

	data, check, err := DetectSMTP(conn, timeout)
	if err != nil {
		if check {
			return nil, nil
		}
		return nil, err
	}

	if !check {
		return nil, nil
	}

	// StartTLS
	startTlsCMD := []byte("STARTTLS\r\n")
	_, err = shared.SendRecvAll(conn, startTlsCMD, timeout)
	conn.Upgrade()

	return plugins.CreateServiceFrom(target, p.Name(), data, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return SMTP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 60
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{25, 587, 465, 2525}
}
