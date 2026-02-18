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
	"encoding/json"
	"testing"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Unit Tests ---

func TestParseRTSPResponse(t *testing.T) {
	t.Parallel()

	t.Run("valid 200 response", func(t *testing.T) {
		raw := "RTSP/1.0 200 OK\r\nCSeq: 42\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\nServer: TestServer/1.0\r\n\r\n"
		resp := parseRTSPResponse(raw)
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.statusCode)
		assert.Equal(t, "OK", resp.statusReason)
		assert.Equal(t, "42", resp.headers["cseq"])
		assert.Equal(t, "OPTIONS, DESCRIBE, SETUP, PLAY", resp.headers["public"])
		assert.Equal(t, "TestServer/1.0", resp.headers["server"])
		assert.Empty(t, resp.body)
	})

	t.Run("401 with auth", func(t *testing.T) {
		raw := "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"test\"\r\n\r\n"
		resp := parseRTSPResponse(raw)
		require.NotNil(t, resp)
		assert.Equal(t, 401, resp.statusCode)
		assert.Equal(t, "Unauthorized", resp.statusReason)
		assert.Equal(t, "Digest realm=\"test\"", resp.headers["www-authenticate"])
	})

	t.Run("response with body", func(t *testing.T) {
		raw := "RTSP/1.0 200 OK\r\nCSeq: 5\r\nContent-Type: application/sdp\r\n\r\nv=0\r\ns=Test\r\n"
		resp := parseRTSPResponse(raw)
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.statusCode)
		assert.Equal(t, "v=0\r\ns=Test\r\n", resp.body)
	})

	t.Run("not RTSP", func(t *testing.T) {
		resp := parseRTSPResponse("HTTP/1.1 200 OK\r\n\r\n")
		assert.Nil(t, resp)
	})

	t.Run("empty input", func(t *testing.T) {
		resp := parseRTSPResponse("")
		assert.Nil(t, resp)
	})

	t.Run("malformed status line - no space after code", func(t *testing.T) {
		resp := parseRTSPResponse("RTSP/1.0 200\r\n\r\n")
		assert.Nil(t, resp)
	})

	t.Run("malformed status line - non-numeric code", func(t *testing.T) {
		resp := parseRTSPResponse("RTSP/1.0 abc OK\r\n\r\n")
		assert.Nil(t, resp)
	})

	t.Run("case-insensitive headers", func(t *testing.T) {
		raw := "RTSP/1.0 200 OK\r\nCSEQ: 1\r\nSERVER: BigServer\r\nPublic: OPTIONS\r\n\r\n"
		resp := parseRTSPResponse(raw)
		require.NotNil(t, resp)
		assert.Equal(t, "1", resp.headers["cseq"])
		assert.Equal(t, "BigServer", resp.headers["server"])
		assert.Equal(t, "OPTIONS", resp.headers["public"])
	})

	t.Run("malformed header line skipped", func(t *testing.T) {
		raw := "RTSP/1.0 200 OK\r\nCSeq: 1\r\nnoColonHere\r\nServer: OK\r\n\r\n"
		resp := parseRTSPResponse(raw)
		require.NotNil(t, resp)
		assert.Equal(t, "1", resp.headers["cseq"])
		assert.Equal(t, "OK", resp.headers["server"])
	})
}

func TestExtractMethods(t *testing.T) {
	t.Parallel()

	t.Run("standard methods", func(t *testing.T) {
		methods := extractMethods("OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN")
		assert.Equal(t, []string{"OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"}, methods)
	})

	t.Run("extra whitespace", func(t *testing.T) {
		methods := extractMethods("  OPTIONS ,  DESCRIBE  ,PLAY  ")
		assert.Equal(t, []string{"OPTIONS", "DESCRIBE", "PLAY"}, methods)
	})

	t.Run("empty string", func(t *testing.T) {
		methods := extractMethods("")
		assert.Nil(t, methods)
	})
}

func TestExtractAuthType(t *testing.T) {
	t.Parallel()

	t.Run("Digest", func(t *testing.T) {
		assert.Equal(t, "Digest", extractAuthType("Digest realm=\"test\", nonce=\"abc\""))
	})

	t.Run("Basic", func(t *testing.T) {
		assert.Equal(t, "Basic", extractAuthType("Basic realm=\"test\""))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", extractAuthType(""))
	})

	t.Run("leading whitespace", func(t *testing.T) {
		assert.Equal(t, "Digest", extractAuthType("  Digest realm=\"test\""))
	})

	t.Run("scheme only, no params", func(t *testing.T) {
		assert.Equal(t, "Bearer", extractAuthType("Bearer"))
	})
}

func TestParseSDP(t *testing.T) {
	t.Parallel()

	t.Run("full SDP with video and audio", func(t *testing.T) {
		body := "v=0\r\n" +
			"o=- 0 0 IN IP4 0.0.0.0\r\n" +
			"s=Live Stream\r\n" +
			"i=Camera feed\r\n" +
			"m=video 0 RTP/AVP 96\r\n" +
			"a=rtpmap:96 H264/90000\r\n" +
			"m=audio 0 RTP/AVP 97\r\n" +
			"a=rtpmap:97 MPEG4-GENERIC/44100/2\r\n"

		sdp := parseSDP(body)
		assert.Equal(t, "Live Stream", sdp.streamName)
		assert.Equal(t, "Camera feed", sdp.streamInfo)
		require.Len(t, sdp.tracks, 2)
		assert.Equal(t, Track{Type: "video", Codec: "H264", ClockRate: "90000"}, sdp.tracks[0])
		assert.Equal(t, Track{Type: "audio", Codec: "MPEG4-GENERIC", ClockRate: "44100"}, sdp.tracks[1])
	})

	t.Run("default s=- placeholder", func(t *testing.T) {
		body := "v=0\r\ns=-\r\nm=video 0 RTP/AVP 96\r\n"
		sdp := parseSDP(body)
		assert.Empty(t, sdp.streamName)
		assert.Len(t, sdp.tracks, 1)
	})

	t.Run("no media tracks", func(t *testing.T) {
		body := "v=0\r\ns=Test\r\n"
		sdp := parseSDP(body)
		assert.Equal(t, "Test", sdp.streamName)
		assert.Empty(t, sdp.tracks)
	})

	t.Run("rtpmap without preceding m= is ignored", func(t *testing.T) {
		body := "v=0\r\na=rtpmap:96 H264/90000\r\n"
		sdp := parseSDP(body)
		assert.Empty(t, sdp.tracks)
	})

	t.Run("empty body", func(t *testing.T) {
		sdp := parseSDP("")
		assert.Empty(t, sdp.streamName)
		assert.Empty(t, sdp.tracks)
	})

	t.Run("LF-only line endings", func(t *testing.T) {
		body := "v=0\ns=LF Only\nm=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n"
		sdp := parseSDP(body)
		assert.Equal(t, "LF Only", sdp.streamName)
		require.Len(t, sdp.tracks, 1)
		assert.Equal(t, "H264", sdp.tracks[0].Codec)
	})

	t.Run("track count capped at 32", func(t *testing.T) {
		body := "v=0\n"
		for i := 0; i < 40; i++ {
			body += "m=video 0 RTP/AVP 96\n"
		}
		sdp := parseSDP(body)
		assert.Len(t, sdp.tracks, 32)
	})
}

func TestBuildOPTIONSRequest(t *testing.T) {
	t.Parallel()

	req := buildOPTIONSRequest("192.168.1.1:554", "42")
	expected := "OPTIONS rtsp://192.168.1.1:554 RTSP/1.0\r\nCSeq: 42\r\n\r\n"
	assert.Equal(t, expected, string(req))
}

func TestBuildDESCRIBERequest(t *testing.T) {
	t.Parallel()

	req := buildDESCRIBERequest("192.168.1.1:554", "99")
	expected := "DESCRIBE rtsp://192.168.1.1:554/ RTSP/1.0\r\nCSeq: 99\r\nAccept: application/sdp\r\n\r\n"
	assert.Equal(t, expected, string(req))
}

// --- Integration Test ---

func TestRtsp(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "rtsp",
			Port:        8554,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				if res == nil {
					return false
				}

				raw, err := json.Marshal(res.Metadata)
				if err != nil {
					return false
				}
				var meta ServiceRtsp
				if err := json.Unmarshal(raw, &meta); err != nil {
					return false
				}

				if meta.StatusCode != 200 {
					return false
				}
				if len(meta.Methods) == 0 {
					return false
				}
				if meta.AuthRequired {
					return false
				}
				return true
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "aler9/rtsp-simple-server",
				ExposedPorts: []string{"8554"},
			},
		},
	}

	p := &Plugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("test failed: %v", err)
			}
		})
	}
}
