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

package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	utils "github.com/chrizzn/fingerprintx/pkg/plugins/pluginutils"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type HTTPPlugin struct {
	analyzer *wappalyzer.Wappalyze
}

func (p *HTTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	// http client with custom dialier to use the provided net.Conn
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req.Header.Set("User-Agent", USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer resp.Body.Close()

	technologies, cpes, _ := p.FingerprintResponse(resp)

	payload := ServiceHTTP{
		Status:          resp.Status,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header,
	}
	if len(technologies) > 0 {
		payload.Technologies = technologies
	}
	if len(cpes) > 0 {
		payload.CPEs = cpes
	}

	fmt.Println("server", resp.Header.Get("Server"))

	return plugins.CreateServiceFrom(target, p.Name(), payload, nil), nil
}
func (p *HTTPPlugin) FingerprintResponse(resp *http.Response) ([]string, []string, error) {
	return fingerprint(resp, p.analyzer)
}

func (p *HTTPPlugin) Name() string {
	return HTTP
}

func (p *HTTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *HTTPPlugin) Priority() int {
	return 0
}

func (p *HTTPPlugin) Ports() []uint16 {
	return []uint16{80, 3000, 4567, 5000, 8000, 8001, 8080, 8081, 8888, 9001, 9080, 9090, 9100}
}
