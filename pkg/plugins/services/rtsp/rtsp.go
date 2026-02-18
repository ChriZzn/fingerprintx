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
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/plugins/shared"
)

const RTSP = "rtsp"

type rtspResponse struct {
	statusCode   int
	statusReason string
	headers      map[string]string
	body         string
}

type sdpInfo struct {
	streamName string
	streamInfo string
	tracks     []Track
}

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func buildOPTIONSRequest(target, cseq string) []byte {
	return []byte("OPTIONS rtsp://" + target + " RTSP/1.0\r\nCSeq: " + cseq + "\r\n\r\n")
}

func buildDESCRIBERequest(target, cseq string) []byte {
	return []byte("DESCRIBE rtsp://" + target + "/ RTSP/1.0\r\nCSeq: " + cseq + "\r\nAccept: application/sdp\r\n\r\n")
}

func parseRTSPResponse(raw string) *rtspResponse {
	// Split headers from body
	headerSection := raw
	body := ""
	if idx := strings.Index(raw, "\r\n\r\n"); idx != -1 {
		headerSection = raw[:idx]
		body = raw[idx+4:]
	}

	lines := strings.Split(headerSection, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse status line: "RTSP/1.0 <code> <reason>"
	statusLine := lines[0]
	if !strings.HasPrefix(statusLine, "RTSP/1.0 ") {
		return nil
	}
	rest := statusLine[len("RTSP/1.0 "):]
	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx == -1 {
		return nil
	}
	code, err := strconv.Atoi(rest[:spaceIdx])
	if err != nil {
		return nil
	}
	reason := rest[spaceIdx+1:]

	// Parse headers into map with lowercase keys
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx == -1 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])
		headers[key] = value
	}

	return &rtspResponse{
		statusCode:   code,
		statusReason: reason,
		headers:      headers,
		body:         body,
	}
}

func extractMethods(publicHeader string) []string {
	if publicHeader == "" {
		return nil
	}
	parts := strings.Split(publicHeader, ",")
	methods := make([]string, 0, len(parts))
	for _, p := range parts {
		m := strings.TrimSpace(p)
		if m != "" {
			methods = append(methods, m)
		}
	}
	return methods
}

func extractAuthType(wwwAuth string) string {
	wwwAuth = strings.TrimSpace(wwwAuth)
	if wwwAuth == "" {
		return ""
	}
	if idx := strings.IndexByte(wwwAuth, ' '); idx != -1 {
		return wwwAuth[:idx]
	}
	return wwwAuth
}

func parseSDP(body string) *sdpInfo {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	lines := strings.Split(body, "\n")

	info := &sdpInfo{}
	var currentTrack *Track

	for _, line := range lines {
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		typ := line[0]
		value := line[2:]

		switch typ {
		case 's':
			if value != "-" {
				info.streamName = value
			}
		case 'i':
			info.streamInfo = value
		case 'm':
			if len(info.tracks) >= 32 {
				continue
			}
			// m=<type> <port> <proto> <fmt>
			fields := strings.Fields(value)
			if len(fields) == 0 {
				continue
			}
			info.tracks = append(info.tracks, Track{Type: fields[0]})
			currentTrack = &info.tracks[len(info.tracks)-1]
		case 'a':
			if currentTrack == nil {
				continue
			}
			// a=rtpmap:<payload> <codec>/<clockRate>[/<channels>]
			if !strings.HasPrefix(value, "rtpmap:") {
				continue
			}
			rtpmapValue := value[len("rtpmap:"):]
			spaceIdx := strings.IndexByte(rtpmapValue, ' ')
			if spaceIdx == -1 {
				continue
			}
			encodingPart := rtpmapValue[spaceIdx+1:]
			slashIdx := strings.IndexByte(encodingPart, '/')
			if slashIdx == -1 {
				continue
			}
			currentTrack.Codec = encodingPart[:slashIdx]
			clockRest := encodingPart[slashIdx+1:]
			if idx := strings.IndexByte(clockRest, '/'); idx != -1 {
				clockRest = clockRest[:idx]
			}
			currentTrack.ClockRate = clockRest
		}
	}

	return info
}

/*
rtsp is a media control protocol used to control the flow of data from a real time
data streaming protocol. rtsp itself does not transport any data. The structure of rtsp
requests is very similar to that of http requests.

To detect the presence of RTSP, this program sends an OPTIONS request, and then validates
the returned header and cseq value. It also sends a best-effort DESCRIBE request to
extract SDP metadata about available streams.

This program was tested with docker run -p 554:8554 aler9/rtsp-simple-server.
The default port for rtsp is 554.
*/
func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	cseq := strconv.Itoa(rand.Intn(10000)) //nolint:gosec
	targetAddr := target.Address.String()

	// Phase 1: OPTIONS
	responseBytes, err := shared.SendRecv(conn, buildOPTIONSRequest(targetAddr, cseq), timeout)
	if err != nil {
		return nil, err
	}
	if len(responseBytes) == 0 {
		return nil, nil
	}

	resp := parseRTSPResponse(string(responseBytes))
	if resp == nil {
		return nil, nil
	}

	// Validate CSeq
	if responseCseq, ok := resp.headers["cseq"]; !ok || strings.TrimSpace(responseCseq) != cseq {
		return nil, nil
	}

	payload := ServiceRtsp{
		StatusCode:   resp.statusCode,
		StatusReason: resp.statusReason,
		ServerInfo:   resp.headers["server"],
		Methods:      extractMethods(resp.headers["public"]),
	}

	if resp.statusCode == 401 {
		payload.AuthRequired = true
		payload.AuthType = extractAuthType(resp.headers["www-authenticate"])
	}

	// Phase 2: DESCRIBE (best-effort, only on 200)
	if resp.statusCode == 200 {
		describeCseq := strconv.Itoa(rand.Intn(10000)) //nolint:gosec
		describeBytes, err := shared.SendRecv(conn, buildDESCRIBERequest(targetAddr, describeCseq), timeout)
		if err == nil && len(describeBytes) > 0 {
			descResp := parseRTSPResponse(string(describeBytes))
			if descResp != nil && descResp.body != "" {
				sdp := parseSDP(descResp.body)
				payload.StreamName = sdp.streamName
				payload.StreamInfo = sdp.streamInfo
				payload.Tracks = sdp.tracks
			}
		}
	}

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
