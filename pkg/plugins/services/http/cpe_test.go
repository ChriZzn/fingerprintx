package http

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractCPEs(t *testing.T) {
	headers := map[string][]string{
		"Server":       {"nginx/1.18.0"},
		"Content-Type": {"text/html"},
	}
	body := []byte(`<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>`)

	cpes := ExtractCPEs(headers, body)
	assert.Contains(t, cpes, "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
	assert.Contains(t, cpes, "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*")
	assert.IsIncreasing(t, cpes)

	assert.Empty(t, ExtractCPEs(map[string][]string{"Content-Type": {"text/plain"}}, []byte("hello")))
}

func TestExtractCPEsConcurrent(t *testing.T) {
	headers := map[string][]string{"Server": {"nginx/1.18.0"}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.Contains(t, ExtractCPEs(headers, nil), "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
		}()
	}
	wg.Wait()
}

func TestWithVersion(t *testing.T) {
	base := "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
	assert.Equal(t, base, withVersion(base, ""))
	assert.Equal(t, "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*", withVersion(base, "1.2.3"))
	assert.Equal(t, `cpe:2.3:a:vendor:product:1.0\+rc1:*:*:*:*:*:*:*`, withVersion(base, "1.0+RC1"))
	// already-pinned version or malformed CPE is left alone
	pinned := "cpe:2.3:a:vendor:product:9.9:*:*:*:*:*:*:*"
	assert.Equal(t, pinned, withVersion(pinned, "1.0"))
	assert.Equal(t, "cpe:/a:vendor:product", withVersion("cpe:/a:vendor:product", "1.0"))
}
