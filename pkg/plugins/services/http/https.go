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

type HTTPSPlugin struct {
	analyzer *wappalyzer.Wappalyze
}

func (p *HTTPSPlugin) Run(
	conn net.Conn,
	timeout time.Duration,
	target plugins.Target,
) (*plugins.Service, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	// https client with custom dialer to use the provided net.Conn
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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

	return plugins.CreateServiceFrom(target, p.Name(), payload, resp.TLS), nil
}
func (p *HTTPSPlugin) FingerprintResponse(resp *http.Response) ([]string, []string, error) {
	return fingerprint(resp, p.analyzer)
}

func (p *HTTPSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *HTTPSPlugin) Priority() int {
	return 1
}

func (p *HTTPSPlugin) Name() string {
	return HTTPS
}

func (p *HTTPSPlugin) Ports() []uint16 {
	return []uint16{443, 9443, 8443}
}

//TODO: fuse them `???
