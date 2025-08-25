package http

import (
	"bytes"
	"encoding/base64"
	"github.com/spaolacci/murmur3"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"sort"
	"strings"
)

func GetFavicon(client *http.Client, baseUrl string, body []byte) (favicon Favicon) {

	// Get potential FavIcon URLs
	hrefs, _, _ := extractPotentialFavIconsURLs(body)
	if len(hrefs) == 0 {
		hrefs = append(hrefs, "favicon.ico")
	}

	for _, href := range hrefs {
		r, err := client.Get(baseUrl + "/" + href)
		if err == nil && r.StatusCode == 200 {
			defer r.Body.Close()
			data, _ := io.ReadAll(r.Body)
			favicon.Hash = CalcMMH3Hash(data)
			favicon.URL = r.Request.URL.String()
			return favicon
		}
	}

	return favicon

}

func CalcMMH3Hash(data []byte) int32 {
	stdBase64 := base64.StdEncoding.EncodeToString(data)
	stdBase64 = insertInto(stdBase64, 76, '\n')
	hasher := murmur3.New32WithSeed(0)
	hasher.Write([]byte(stdBase64))
	return int32(hasher.Sum32())
}

func insertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}
func extractPotentialFavIconsURLs(resp []byte) (candidates []string, baseHref string, err error) {
	doc, err := html.Parse(bytes.NewReader(resp))
	if err != nil {
		return nil, "", err
	}

	var processNode func(*html.Node)
	processNode = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Handle base tag
			if n.Data == "base" {
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						baseHref = strings.TrimSpace(attr.Val)
						break
					}
				}
			}

			// Handle link tags
			if n.Data == "link" {
				var rel, href string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "rel":
						rel = strings.ToLower(strings.TrimSpace(attr.Val))
					case "href":
						href = strings.TrimSpace(attr.Val)
					}
				}

				if href != "" {
					for _, tok := range strings.Fields(rel) {
						switch tok {
						case "icon", "shortcut", "shortcut-icon", "apple-touch-icon", "mask-icon", "alternate":
							candidates = append(candidates, href)
							return
						}
					}
				}
			}
		}

		// Recursively process child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			processNode(c)
		}
	}

	processNode(doc)

	// Sort candidates (same logic as before)
	sort.SliceStable(candidates, func(i, j int) bool {
		ai := strings.HasSuffix(strings.ToLower(candidates[i]), ".ico")
		aj := strings.HasSuffix(strings.ToLower(candidates[j]), ".ico")
		if ai == aj {
			return candidates[i] < candidates[j]
		}
		return ai && !aj
	})

	return candidates, baseHref, nil
}
