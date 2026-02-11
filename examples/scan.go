package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"github.com/chrizzn/fingerprintx/pkg/scan"
)

func main() {
	// setup the scan config (mirrors command line options)
	// Use a context to control overall scan timeout and cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fxConfig := scan.Config{
		Ctx:            ctx,
		DefaultTimeout: time.Duration(2) * time.Second,
		FastMode:       false,
		Verbose:        false,
	}

	// create a target list to scan
	ip, _ := netip.ParseAddr("146.148.61.165")
	target := plugins.Target{
		Address:   netip.AddrPortFrom(ip, 443),
		Transport: plugins.TCP,
	}
	targets := make([]plugins.Target, 1)
	targets = append(targets, target)

	// run the scan
	results, err := scan.Scan(targets, fxConfig)
	if err != nil {
		log.Fatalf("error: %s\n", err)
	}

	// process the results
	for _, result := range results {
		fmt.Printf("%s:%d (%s/%s)\n", result.Host, result.Port, result.Transport, result.Protocol)
	}
}
