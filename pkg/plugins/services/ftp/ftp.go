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
	"net"
	"regexp"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	utils "github.com/chrizzn/fingerprintx/pkg/plugins/pluginutils"
)

var ftpResponse = regexp.MustCompile(`^\d{3}[- ](.*)\r`)

const FTP = "ftp"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	matches := ftpResponse.FindStringSubmatch(string(response))
	if matches == nil {
		return nil, nil
	}

	payload := ServiceFTP{
		Banner: string(response),
	}

	return plugins.CreateServiceFrom(target, p.Name(), payload, nil), nil
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
