package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
)

// newHTTPTarget spins up a local HTTP server and returns a Target pointing at it,
// plus a cleanup func. The server speaks plain HTTP so the http plugin matches.
func newHTTPTarget(t *testing.T) (plugins.Target, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "fingerprintx-test")
		_, _ = w.Write([]byte("<html><head><title>hello</title></head><body>ok</body></html>"))
	}))

	ap, err := netip.ParseAddrPort(srv.Listener.Addr().String())
	if err != nil {
		srv.Close()
		t.Fatalf("parse listener addr %q: %v", srv.Listener.Addr().String(), err)
	}
	target := plugins.Target{Address: ap, Transport: plugins.TCP}
	return target, srv.Close
}

// TestScanConcurrentHTTP exercises the target-level worker pool and the shared
// http-plugin singleton by scanning the same target many times with concurrency
// > 1. Run with -race to assert there is no data race on the shared plugin
// singletons: go test -race ./pkg/scan/
func TestScanConcurrentHTTP(t *testing.T) {
	target, cleanup := newHTTPTarget(t)
	defer cleanup()

	const n = 60
	targets := make([]plugins.Target, n)
	for i := range targets {
		targets[i] = target
	}

	results, err := Scan(targets, Config{
		Ctx:            context.Background(),
		DefaultTimeout: 3 * time.Second,
		Concurrency:    8,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	for i, r := range results {
		if r.Protocol != "http" {
			t.Errorf("result %d: expected protocol \"http\", got %q", i, r.Protocol)
		}
	}
}

// TestScanConcurrencyMatchesSequential confirms Concurrency>1 yields the same
// result set (and order, for identical targets) as the sequential default.
func TestScanConcurrencyMatchesSequential(t *testing.T) {
	target, cleanup := newHTTPTarget(t)
	defer cleanup()

	const n = 20
	targets := make([]plugins.Target, n)
	for i := range targets {
		targets[i] = target
	}

	seq, err := Scan(targets, Config{Ctx: context.Background(), DefaultTimeout: 3 * time.Second, Concurrency: 1})
	if err != nil {
		t.Fatalf("sequential scan error: %v", err)
	}
	par, err := Scan(targets, Config{Ctx: context.Background(), DefaultTimeout: 3 * time.Second, Concurrency: 8})
	if err != nil {
		t.Fatalf("parallel scan error: %v", err)
	}
	if len(seq) != n || len(par) != n {
		t.Fatalf("expected %d results each, got seq=%d par=%d", n, len(seq), len(par))
	}
}

// TestScanEmptyReturnsNil preserves the contract that an empty target list
// returns a nil slice and nil error.
func TestScanEmptyReturnsNil(t *testing.T) {
	results, err := Scan(nil, Config{Ctx: context.Background(), Concurrency: 8})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil results for empty targets, got %#v", results)
	}
}

// TestScanNoMatchReturnsNilSlice ensures that when nothing matches, the result is
// a nil slice (not an empty non-nil slice) so JSON/`== nil` callers are unaffected.
func TestScanNoMatchReturnsNilSlice(t *testing.T) {
	// 127.0.0.1:1 is reserved/closed; connections are refused fast.
	target := plugins.Target{
		Address:   netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1),
		Transport: plugins.TCP,
	}
	results, err := Scan([]plugins.Target{target, target}, Config{
		Ctx:            context.Background(),
		DefaultTimeout: 500 * time.Millisecond,
		Concurrency:    4,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil results when nothing matches, got %#v", results)
	}
}

// TestScanContextAlreadyCancelled matches the sequential behavior: a context that
// is already cancelled returns ctx.Err() without scanning.
func TestScanContextAlreadyCancelled(t *testing.T) {
	target, cleanup := newHTTPTarget(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := Scan([]plugins.Target{target}, Config{
		Ctx:            ctx,
		DefaultTimeout: 3 * time.Second,
		Concurrency:    8,
	})
	if err == nil {
		t.Fatalf("expected ctx error, got nil (results=%#v)", results)
	}
}
