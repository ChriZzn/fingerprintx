package scan

import (
	"github.com/chrizzn/fingerprintx/pkg/plugins"
	"slices"
	"sort"
)

// PluginMatrix stores plugins organized by protocol with priority sorting
type PluginMatrix struct {
	tcpPlugins []plugins.Plugin
	udpPlugins []plugins.Plugin
	AllPlugins []plugins.Plugin
}

// NewPluginMatrix initializes a new PluginMatrix with sorted plugins
func NewPluginMatrix() *PluginMatrix {
	pm := &PluginMatrix{
		tcpPlugins: make([]plugins.Plugin, 0),
		udpPlugins: make([]plugins.Plugin, 0),
	}

	// Add TCP plugins
	if tcpPlugins, exists := plugins.Plugins[plugins.TCP]; exists {
		pm.tcpPlugins = append(pm.tcpPlugins, tcpPlugins...)
	}

	// Add UDP plugins
	if udpPlugins, exists := plugins.Plugins[plugins.UDP]; exists {
		pm.udpPlugins = append(pm.udpPlugins, udpPlugins...)
	}

	// Sort plugins by priority
	sort.Slice(pm.tcpPlugins, func(i, j int) bool {
		return pm.tcpPlugins[i].Priority() < pm.tcpPlugins[j].Priority()
	})
	sort.Slice(pm.udpPlugins, func(i, j int) bool {
		return pm.udpPlugins[i].Priority() < pm.udpPlugins[j].Priority()
	})

	// add to all
	pm.AllPlugins = append(pm.tcpPlugins, pm.udpPlugins...)

	return pm
}

// GetPluginByTarget returns the appropriate plugin and its ID for a given target
func (pm *PluginMatrix) GetPluginByTarget(target plugins.Target) plugins.Plugin {
	var pluginList []plugins.Plugin

	// Select the appropriate plugin list based on transport protocol
	if target.Transport == plugins.TCP {
		pluginList = pm.tcpPlugins
	} else if target.Transport == plugins.UDP {
		pluginList = pm.udpPlugins
	}

	// Check for port priority first
	port := target.Address.Port()
	for _, plugin := range pluginList {
		if slices.Contains(plugin.Ports(), port) {
			return plugin
		}

	}

	return nil
}

// GetPluginsByTargetPriority returns plugins for the target's transport, with any
// plugin that owns the target port moved to the front (preserving priority order
// among matches). This makes brute-force mode try the port's expected service first
// while still falling through to every other plugin if it doesn't match.
func (pm *PluginMatrix) GetPluginsByTargetPriority(target plugins.Target) []plugins.Plugin {
	all := pm.GetPluginsByTransport(target.Transport)
	port := target.Address.Port()

	ordered := make([]plugins.Plugin, 0, len(all))
	rest := make([]plugins.Plugin, 0, len(all))
	for _, plugin := range all {
		if slices.Contains(plugin.Ports(), port) {
			ordered = append(ordered, plugin)
		} else {
			rest = append(rest, plugin)
		}
	}
	return append(ordered, rest...)
}

// GetPluginsByTransport retrieves a list of plugins based on the specified transport protocol (TCP or UDP).
func (pm *PluginMatrix) GetPluginsByTransport(transport plugins.Protocol) []plugins.Plugin {
	if transport == plugins.TCP {
		return pm.tcpPlugins
	} else if transport == plugins.UDP {
		return pm.udpPlugins
	} else {
		return nil
	}
}
