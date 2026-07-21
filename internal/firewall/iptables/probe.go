// Package iptables contains iptables-specific capability detection. It does
// not implement rule application.
package iptables

import (
	"context"
	"sort"

	"digitdojo-shield/internal/firewall/backend"
)

var requiredCommands = []string{
	"iptables",
	"iptables-restore",
	"iptables-save",
	"ip6tables",
	"ip6tables-restore",
	"ip6tables-save",
}

type Probe struct {
	locator backend.CommandLocator
}

func NewProbe(locator backend.CommandLocator) *Probe {
	return &Probe{locator: locator}
}

func (p *Probe) Name() backend.Name {
	return backend.IPTables
}

func (p *Probe) Detect(ctx context.Context) backend.Capability {
	capability := backend.Capability{Name: backend.IPTables, Commands: make(map[string]string)}
	if err := ctx.Err(); err != nil {
		capability.Reason = err.Error()
		return capability
	}
	if p.locator == nil {
		capability.Missing = append([]string(nil), requiredCommands...)
		capability.Reason = "command locator is unavailable"
		return capability
	}
	for _, command := range requiredCommands {
		path, err := p.locator.LookPath(command)
		if err != nil {
			capability.Missing = append(capability.Missing, command)
			continue
		}
		capability.Commands[command] = path
	}
	sort.Strings(capability.Missing)
	capability.Detected = len(capability.Missing) == 0
	if capability.Detected {
		capability.Reason = "IPv4 and IPv6 iptables commands detected; kernel behavior is unverified"
	} else {
		capability.Reason = "required IPv4 or IPv6 iptables commands are missing"
	}
	return capability
}
