// Package nftables contains the nftables capability probe and privileged
// implementation. Production mutation remains gated by firewall.Controller.
package nftables

import (
	"context"

	"digitdojo-shield/internal/firewall/backend"
)

type Probe struct {
	locator          backend.CommandLocator
	runtimeChecks    bool
	versionCheck     func(context.Context, string) (Version, error)
	environmentCheck func() error
}

func NewProbe(locator backend.CommandLocator) *Probe {
	return &Probe{locator: locator}
}

// NewRuntimeProbe validates the Linux capability and nftables version needed
// by the production backend in addition to command discovery.
func NewRuntimeProbe(locator backend.CommandLocator) *Probe {
	return &Probe{
		locator:          locator,
		runtimeChecks:    true,
		versionCheck:     CheckNFTVersion,
		environmentCheck: CheckFirewallEnvironment,
	}
}

func (p *Probe) Name() backend.Name {
	return backend.NFTables
}

func (p *Probe) Detect(ctx context.Context) backend.Capability {
	capability := backend.Capability{Name: backend.NFTables, Commands: make(map[string]string)}
	if err := ctx.Err(); err != nil {
		capability.Reason = err.Error()
		return capability
	}
	if p.locator == nil {
		capability.Missing = []string{"nft"}
		capability.Reason = "command locator is unavailable"
		return capability
	}
	path, err := p.locator.LookPath("nft")
	if err != nil {
		capability.Missing = []string{"nft"}
		capability.Reason = "nft userspace command not found"
		return capability
	}
	capability.Commands["nft"] = path
	if p.runtimeChecks {
		version, versionErr := p.versionCheck(ctx, path)
		if versionErr != nil {
			capability.Missing = []string{"nft>=" + MinimumSupportedVersion}
			capability.Reason = versionErr.Error()
			return capability
		}
		capability.Commands["nft_version"] = version.String()
		if environmentErr := p.environmentCheck(); environmentErr != nil {
			capability.Missing = []string{"Linux with CAP_NET_ADMIN"}
			capability.Reason = environmentErr.Error()
			return capability
		}
	}
	capability.Detected = true
	if p.runtimeChecks {
		capability.Reason = "supported nftables userspace and CAP_NET_ADMIN detected; kernel behavior is unverified"
	} else {
		capability.Reason = "nft userspace command detected; kernel behavior is unverified"
	}
	return capability
}
