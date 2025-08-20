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

package pop3

import (
	"net"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	utils "github.com/chrizzn/fingerprintx/pkg/plugins/pluginutils"
)

type Plugin struct{} // POP3

const POP3 = "pop3"

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func DetectPOP3(conn net.Conn, timeout time.Duration, tls bool) (string, bool, error) {
	// read initial response from server
	initialResponse, err := utils.Recv(conn, timeout)
	if err != nil {
		return "", false, err
	}
	if len(initialResponse) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	// send a bogus command and read error response
	errResponse, err := utils.SendRecv(conn, []byte("Not a command \r\n"), timeout)
	if err != nil {
		return "", false, err
	}
	if len(errResponse) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	isPOP3 := false
	if strings.HasPrefix(string(initialResponse), "+OK") &&
		strings.HasPrefix(string(errResponse), "-ERR") {
		isPOP3 = true
	}

	if !isPOP3 {
		// no ? :(
		return "", true, &utils.InvalidResponseErrorInfo{
			Service: POP3,
			Info:    "did not get expected banner for POP3",
		}
	}

	return string(initialResponse[4:]), true, nil
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	result, check, err := DetectPOP3(conn, timeout, false)

	if check && err != nil { // service is not running POP3
		return nil, nil
	} else if !check && err != nil { // plugin error
		return nil, err
	}

	// service is running POP3
	payload := ServicePOP3{
		Banner: result,
	}
	return plugins.CreateServiceFrom(target, p.Name(), payload, nil), nil
}

func (p *Plugin) Name() string {
	return POP3
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 120
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{110, 995}
}
