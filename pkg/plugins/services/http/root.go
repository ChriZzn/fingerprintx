package http

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"io"
	"net/http"
)

const HTTP = "http"
const HTTPS = "https"
const USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

func init() {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		panic("unable to initialize wappalyzer library")
	}
	plugins.RegisterPlugin(&HTTPPlugin{analyzer: wappalyzerClient})
	plugins.RegisterPlugin(&HTTPSPlugin{analyzer: wappalyzerClient})
}

func fingerprint(resp *http.Response, analyzer *wappalyzer.Wappalyze) ([]string, []string, error) {
	var technologies, cpes []string
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	fingerprint := analyzer.FingerprintWithInfo(resp.Header, data)
	for tech, appInfo := range fingerprint {
		technologies = append(technologies, tech)
		if cpe := appInfo.CPE; cpe != "" {
			cpes = append(cpes, cpe)
		}
	}

	return technologies, cpes, nil
}

//TODO: consolidate ... -> maybe reuse net.Conn ??

//TODO: ALSO USE HTTP only and not NAME https!!

//TODO: webalyzer needed??
