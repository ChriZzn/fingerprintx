package http

import (
	"context"
	"fmt"
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const HTTP = "http"
const USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

func init() {
	wac, err := wappalyzer.New()
	if err != nil {
		panic("unable to initialize wappalyzer library")
	}
	plugins.RegisterPlugin(&Plugin{wappalyzer: wac})
}

type Plugin struct {
	wappalyzer  *wappalyzer.Wappalyze
	FaviconHash int32 `json:"favicon_hash,omitempty"`
}

func extractTitle(body []byte) (string, error) {
	z := html.NewTokenizer(strings.NewReader(string(body)))
	inTitle := false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if z.Err() == io.EOF {
				return "", io.EOF
			}
			return "", z.Err()
		case html.StartTagToken:
			t := z.Token()
			if t.Data == "title" {
				inTitle = true
			}
		case html.TextToken:
			if inTitle {
				title := strings.TrimSpace(string(z.Text()))
				if title != "" {
					return title, nil
				}
			}
		case html.EndTagToken:
			t := z.Token()
			if t.Data == "title" {
				inTitle = false
			}
		}
	}
}

func fingerprint(resp *http.Response, analyzer *wappalyzer.Wappalyze) ([]string, []string, []string, error) {
	var technologies, cpes, categories []string
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, err
	}

	fingerprint := analyzer.FingerprintWithInfo(resp.Header, data)
	for tech, appInfo := range fingerprint {
		technologies = append(technologies, tech)
		if cpe := appInfo.CPE; cpe != "" {
			cpes = append(cpes, cpe)
		}
		if cat := appInfo.Categories; cat != nil {
			categories = append(categories, cat...)
		}
	}

	return technologies, cpes, categories, nil
}

func HTTPClient(conn *plugins.FingerprintConn, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return conn, nil
		},
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return conn, nil
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Set default User-Agent for all requests made by this client
	originalTransport := client.Transport
	client.Transport = &userAgentTransport{
		transport: originalTransport,
	}

	return client
}

type userAgentTransport struct {
	transport http.RoundTripper
}

// RoundTrip implements the RoundTripper interface
func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", USERAGENT)
	return t.transport.RoundTrip(req)
}

func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {

	client := HTTPClient(conn, timeout)
	service := &ServiceHTTP{}

	// Build URI
	scheme := "http"
	if conn.TLS() != nil {
		scheme = "https"
	}

	baseURL := fmt.Sprintf("%s://%s/", scheme, target.String())

	// Request
	resp, err := client.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Enrich Data
	body, err := io.ReadAll(resp.Body)

	technologies, CPEs, cats, e := fingerprint(resp, p.wappalyzer)
	if e == nil {
		service.CPEs = CPEs
		service.Technologies = technologies
		service.Categories = cats
	}

	// HTTP Data
	service.Status = resp.StatusCode
	service.Server = resp.Header.Get("Server")
	if title, err := extractTitle(body); err == nil {
		service.Title = title
	}

	// Favicon
	service.Favicon = GetFavicon(client, baseURL, body)

	// Headers
	for key, values := range resp.Header {
		for _, value := range values {
			service.Headers = append(service.Headers, Header{
				Key:   key,
				Value: value,
			})
		}
	}

	return plugins.CreateServiceFrom(target, scheme, service, conn.TLS()), nil
}

func (p *Plugin) Name() string {
	return HTTP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 0
}

func (p *Plugin) Ports() []uint16 {
	return []uint16{80, 3000, 4567, 5000, 8000, 8001, 8080, 8081, 8888, 9001, 9080, 9090, 9100, 443, 9443, 8443}
}
