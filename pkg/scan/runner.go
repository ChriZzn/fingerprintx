package scan

import (
	"fmt"
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"log"
)

func (c *Config) RunTargetScan(target plugins.Target) (*plugins.Service, error) {

	pluginMatrix := NewPluginMatrix()

	if c.FastMode {
		// search and executes the Plugin
		plugin := pluginMatrix.GetPluginByTarget(target)
		if plugin == nil {
			return nil, fmt.Errorf("unable to find plugin for target %v", target)
		}
		// connect
		conn, err := plugins.Connect(c.Ctx, target, c.DefaultTimeout)
		if err != nil {
			return nil, fmt.Errorf("error connecting to target, err = %w", err)
		}

		result, err := runPlugin(conn, target, c, plugin)
		if result == nil && c.FallBack == true {
			return fallback(target, conn)
		}
		return result, err

	}

	// Bruteforce until the service is found
	for _, plugin := range pluginMatrix.GetPluginsByTransport(target.Transport) {
		// Check for cancellation before each plugin attempt
		select {
		case <-c.Ctx.Done():
			return nil, c.Ctx.Err()
		default:
		}

		//connect
		conn, err := plugins.Connect(c.Ctx, target, c.DefaultTimeout)
		if err != nil {
			return nil, fmt.Errorf("error connecting to target, err = %w", err)
		}
		// execute
		result, err := runPlugin(conn, target, c, plugin)
		if err != nil && c.Verbose {
			log.Printf("error: %v scanning %v\n", err, target.Address.String())
		}
		if result != nil && err == nil {
			// identified plugin match

			return result, nil
		}
	}

	if c.FallBack == true {
		conn, _ := plugins.Connect(c.Ctx, target, c.DefaultTimeout)
		return fallback(target, conn)
	}

	return nil, nil
}

// runPlugin executes the provided plugin for the given target using the supplied connection and configuration.
// It logs the operation's start and completion if verbose mode is enabled in the configuration.
// The function returns the service information obtained from the plugin or an error if the operation fails.
func runPlugin(
	conn *plugins.FingerprintConn,
	target plugins.Target,
	config *Config,
	plugin plugins.Plugin,
) (result *plugins.Service, err error) {

	// Recover from panics in plugins to prevent crashing the entire process.
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = fmt.Errorf("plugin %v panicked: %v", plugins.CreatePluginID(plugin), r)
			if config.Verbose {
				log.Printf("%v %v-> plugin %v panicked: %v\n",
					target.Address.String(),
					target.Host,
					plugins.CreatePluginID(plugin),
					r,
				)
			}
		}
	}()

	// Log probe start.
	if config.Verbose {
		log.Printf("%v %v-> scanning %v\n",
			target.Address.String(),
			target.Host,
			plugins.CreatePluginID(plugin),
		)
	}

	result, err = plugin.Run(conn, config.DefaultTimeout, target)

	// Log probe completion.
	if config.Verbose {
		log.Printf(
			"%v %v-> completed %v\n",
			target.Address.String(),
			target.Host,
			plugins.CreatePluginID(plugin),
		)
	}
	return result, err
}

// fallback initializes a default Service object for the provided Target and returns it.
func fallback(target plugins.Target, conn *plugins.FingerprintConn) (*plugins.Service, error) {
	return plugins.CreateServiceFrom(target, "unknown", nil, conn.TLS()), nil
}
