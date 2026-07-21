package nftables

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"digitdojo-shield/internal/firewall/backend"
)

const (
	tableName       = "digitdojo_shield"
	baseChainName   = "shield_input"
	policyChainName = "shield_policy"
)

func renderRuleset(state backend.DesiredState, now time.Time) ([]byte, error) {
	normalized, err := state.Normalize(now)
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString("destroy table inet " + tableName + "\n")
	builder.WriteString("add table inet " + tableName + "\n")
	writeAddressSet(&builder, "whitelist_v4", "ipv4_addr", ipv4Addresses(normalized.Whitelist))
	writeAddressSet(&builder, "whitelist_v6", "ipv6_addr", ipv6Addresses(normalized.Whitelist))
	writeAddressSet(&builder, "permanent_bans_v4", "ipv4_addr", ipv4Addresses(normalized.PermanentBans))
	writeAddressSet(&builder, "permanent_bans_v6", "ipv6_addr", ipv6Addresses(normalized.PermanentBans))
	writeTemporarySet(&builder, "temporary_bans_v4", "ipv4_addr", normalized.TemporaryBans, true, now)
	writeTemporarySet(&builder, "temporary_bans_v6", "ipv6_addr", normalized.TemporaryBans, false, now)
	builder.WriteString("add chain inet " + tableName + " " + policyChainName + "\n")
	builder.WriteString("add chain inet " + tableName + " " + baseChainName + " { type filter hook input priority -10; policy accept; }\n")
	builder.WriteString("add rule inet " + tableName + " " + baseChainName + " jump " + policyChainName + "\n")
	builder.WriteString("add rule inet " + tableName + " " + policyChainName + " ip saddr @whitelist_v4 accept\n")
	builder.WriteString("add rule inet " + tableName + " " + policyChainName + " ip6 saddr @whitelist_v6 accept\n")
	builder.WriteString("add rule inet " + tableName + " " + policyChainName + " ip saddr @permanent_bans_v4 drop\n")
	builder.WriteString("add rule inet " + tableName + " " + policyChainName + " ip6 saddr @permanent_bans_v6 drop\n")
	builder.WriteString("add rule inet " + tableName + " " + policyChainName + " ip saddr @temporary_bans_v4 drop\n")
	builder.WriteString("add rule inet " + tableName + " " + policyChainName + " ip6 saddr @temporary_bans_v6 drop\n")
	return []byte(builder.String()), nil
}

func writeAddressSet(builder *strings.Builder, name, addressType string, addresses []netip.Addr) {
	fmt.Fprintf(builder, "add set inet %s %s { type %s;", tableName, name, addressType)
	if len(addresses) > 0 {
		builder.WriteString(" elements = { ")
		for index, address := range addresses {
			if index > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(address.String())
		}
		builder.WriteString(" }; ")
	}
	builder.WriteString(" }\n")
}

func writeTemporarySet(builder *strings.Builder, name, addressType string, bans []backend.TemporaryBan, ipv4 bool, now time.Time) {
	fmt.Fprintf(builder, "add set inet %s %s { type %s; flags timeout;", tableName, name, addressType)
	written := 0
	for _, ban := range bans {
		if ban.Address.Is4() != ipv4 || !ban.ExpiresAt.After(now) {
			continue
		}
		if written == 0 {
			builder.WriteString(" elements = { ")
		} else {
			builder.WriteString(", ")
		}
		seconds := int64((ban.ExpiresAt.Sub(now) + time.Second - 1) / time.Second)
		fmt.Fprintf(builder, "%s timeout %ds", ban.Address, seconds)
		written++
	}
	if written > 0 {
		builder.WriteString(" }; ")
	}
	builder.WriteString(" }\n")
}

func ipv4Addresses(addresses []netip.Addr) []netip.Addr {
	return filterAddresses(addresses, true)
}

func ipv6Addresses(addresses []netip.Addr) []netip.Addr {
	return filterAddresses(addresses, false)
}

func filterAddresses(addresses []netip.Addr, ipv4 bool) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Is4() == ipv4 {
			result = append(result, address)
		}
	}
	return result
}
