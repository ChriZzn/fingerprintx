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

package rtsp

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

const (
	RtspMagicHeader        = "RTSP/1.0"
	RtspMagicHeaderLength  = 8
	RtspCseqHeader         = "CSeq: "
	RtspCseqHeaderLength   = 6
	RtspServerHeader       = "Server: "
	RtspServerHeaderLength = 8
	RtspNewlineLength      = 2
	RTSP                   = "rtsp"
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

/*
rtsp is a media control protocol used to control the flow of data from a real time
data streaming protocol. rtsp itself does not transport any data. The structure of rtsp
requests is very similar to that of http requests.

To detect the presence of RTSP, this program sends an OPTIONS request, and then validates
the returned header and cseq value.

This program was tested with docker run -p 554:8554 aler9/rtsp-simple-server.
The default port for rtsp is 554.
*/
func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	cseq := strconv.Itoa(rand.Intn(10000)) //nolint:gosec

	// Use the actual target host instead of hardcoded example.com
	requestString := strings.Join([]string{
		"OPTIONS rtsp://", target.Address.String(), " RTSP/1.0\r\n",
		"CSeq: ", cseq, "\r\n",
		"\r\n",
	}, "")

	requestBytes := []byte(requestString)

	responseBytes, err := shared.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(responseBytes) == 0 {
		return nil, nil
	}
	response := string(responseBytes)

	// Check minimum response length
	if len(response) < RtspMagicHeaderLength {
		return nil, nil
	}

	// Verify RTSP header
	if !strings.HasPrefix(response, RtspMagicHeader) {
		return nil, nil
	}

	// Parse CSeq
	cseqStart := strings.Index(response, RtspCseqHeader)
	if cseqStart == -1 {
		return nil, nil
	}

	cseqValueStart := cseqStart + RtspCseqHeaderLength
	cseqEnd := strings.Index(response[cseqValueStart:], "\r\n")
	if cseqEnd == -1 {
		return nil, nil
	}
	responseCseq := strings.TrimSpace(response[cseqValueStart : cseqValueStart+cseqEnd])
	if responseCseq != cseq {
		return nil, nil
	}

	payload := ServiceRtsp{}
	payload.ServerInfo = strings.TrimSpace(response)

	return plugins.CreateServiceFrom(target, p.Name(), payload, conn.TLS()), nil
}
func (p *Plugin) Name() string {
	return RTSP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 1001
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{554}
}
