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
		conn, err := plugins.Connect(target)
		if err != nil {
			return nil, fmt.Errorf("error connecting to target, err = %w", err)
		}
		return runPlugin(conn, target, c, plugin)
	}

	// Bruteforce until the service is found
	for _, plugin := range pluginMatrix.GetPluginsByTransport(target.Transport) {
		//connect
		conn, err := plugins.Connect(target)
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
) (*plugins.Service, error) {

	// Log probe start.
	if config.Verbose {
		log.Printf("%v %v-> scanning %v\n",
			target.Address.String(),
			target.Host,
			plugins.CreatePluginID(plugin),
		)
	}

	result, err := plugin.Run(conn, config.DefaultTimeout, target)
	//TODO: FALL BACK FOR NONE/uknown/just SSL Plugin ?? (185.8.24.152:23)

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
