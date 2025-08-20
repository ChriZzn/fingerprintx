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
	"net"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	utils "github.com/chrizzn/fingerprintx/pkg/plugins/pluginutils"
)

type Plugin struct{}

const SMTP = "smtp"

type Data struct {
	Banner      string
	AuthMethods []string
}

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

func DetectSMTP(conn net.Conn, timeout time.Duration) (Data, bool, error) {
	protocol := SMTP

	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError := handleSMTPConn(response)
	if !isSMTP && !smtpError {
		return Data{}, true, &utils.InvalidResponseError{Service: protocol}
	}

	banner := make([]byte, len(response))
	copy(banner, response)

	// Send the EHLO message
	smtpEhloCommand := []byte("EHLO example.com\r\n")
	response, err = utils.SendRecv(conn, smtpEhloCommand, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError = handleSMTPHelo(response)
	if !isSMTP {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: protocol,
			Info:    "invalid SMTP Helo response",
		}
	}

	// a valid smtperror means it is smtp
	if smtpError {
		data := Data{
			Banner: string(banner),
		}

		return data, true, nil
	}

	if isSMTP {
		data := Data{
			Banner:      string(banner),
			AuthMethods: strings.Split(strings.ReplaceAll(string(response), "-", " "), " "),
		}

		return data, true, nil
	}

	return Data{}, true, &utils.InvalidResponseError{Service: protocol}
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, check, err := DetectSMTP(conn, timeout)
	if err == nil && check {
		payload := ServiceSMTP{
			Banner:      data.Banner,
			AuthMethods: data.AuthMethods,
		}
		//TODO: ADD STARTTLS
		return plugins.CreateServiceFrom(target, p.Name(), payload, nil), nil
	} else if err != nil && check {
		return nil, nil
	}
	return nil, err
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
