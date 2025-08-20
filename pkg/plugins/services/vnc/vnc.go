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

package vnc

import (
	"fmt"
	"net"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	utils "github.com/chrizzn/fingerprintx/pkg/plugins/pluginutils"
)

type Plugin struct{}

const VNC = "vnc"

// Check if the response is from a VNC server
// https://datatracker.ietf.org/doc/html/rfc6143#section-7.1
// Handshaking begins by the server sending the client a ProtocolVersion message.
//
// The ProtocolVersion message consists of 12 bytes interpreted as a
//
//	string of ASCII characters in the format "RFB xxx.yyy\n" where xxx
//	and yyy are the major and minor version numbers, left-padded with
//	zeros:
//
//	    RFB 003.008\n (hex 52 46 42 20 30 30 33 2e 30 30 38 0a)
func checkVNC(data []byte) (string, error) {
	msgLength := len(data)
	if msgLength != 12 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "incorrect message length",
		}
	}

	// starts with RFB
	if data[0] != 0x52 || data[1] != 0x46 || data[2] != 0x42 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "invalid RFB preamble",
		}
	}

	// 8th element is '.' and the last is '\n'
	if data[7] != 0x2e || data[11] != 0x0a {
		return "", &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "missing ProtocolVersion characters",
		}
	}

	return string(data[4:11]), nil
}

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

	info, err := checkVNC(response)
	if err != nil {
		return nil, nil
	}
	fmt.Println(info) //TODO enrich type

	return plugins.CreateServiceFrom(target, p.Name(), ServiceVNC{}, nil), nil
}

func (p *Plugin) Name() string {
	return VNC
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 265
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{5900, 5901, 5910}
}
