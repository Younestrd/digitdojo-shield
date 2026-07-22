package nftables

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const MinimumSupportedVersion = "1.0.9"

const (
	capNetAdmin = 12
	capSysAdmin = 21
)

var nftVersionPattern = regexp.MustCompile(`(?i)\bnftables\s+v?(\d+)\.(\d+)\.(\d+)\b`)

// Version is a comparable nftables userspace version.
type Version struct {
	Major int
	Minor int
	Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) AtLeast(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch >= other.Patch
}

func minimumVersion() Version { return Version{Major: 1, Minor: 0, Patch: 9} }

func ParseVersion(output string) (Version, error) {
	matches := nftVersionPattern.FindStringSubmatch(output)
	if len(matches) != 4 {
		return Version{}, fmt.Errorf("unable to parse nftables version from %q", strings.TrimSpace(output))
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// CheckNFTVersion verifies the version required by the Shield transaction and
// cleanup grammar. It does not modify firewall state.
func CheckNFTVersion(ctx context.Context, path string) (Version, error) {
	if ctx == nil {
		return Version{}, fmt.Errorf("nftables version check requires a non-nil context")
	}
	output, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return Version{}, fmt.Errorf("run nft --version: %w: %s", err, strings.TrimSpace(string(output)))
	}
	version, err := ParseVersion(string(output))
	if err != nil {
		return Version{}, err
	}
	if !version.AtLeast(minimumVersion()) {
		return Version{}, fmt.Errorf("nftables %s is unsupported; DigitDojo Shield requires nftables >= %s", version, MinimumSupportedVersion)
	}
	return version, nil
}

// CheckFirewallEnvironment verifies the minimum runtime prerequisites for a
// real nftables backend. It does not inspect or modify rules.
func CheckFirewallEnvironment() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("nftables backend requires Linux; current operating system is %s", runtime.GOOS)
	}
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		return fmt.Errorf("linux network namespace support is unavailable: %w", err)
	}
	if err := requireCapability(capNetAdmin, "CAP_NET_ADMIN", "nftables can be inspected but Shield cannot create or modify rules"); err != nil {
		return err
	}
	return nil
}

// CheckIntegrationEnvironment extends the backend requirements with the
// privilege needed to create network namespaces and veth pairs for tests.
func CheckIntegrationEnvironment() error {
	if err := CheckFirewallEnvironment(); err != nil {
		return err
	}
	if err := requireCapability(capSysAdmin, "CAP_SYS_ADMIN", "the namespace integration suite cannot create isolated network namespaces"); err != nil {
		return err
	}
	return nil
}

func requireCapability(bit uint, name, consequence string) error {
	capabilities, err := effectiveCapabilities()
	if err != nil {
		return fmt.Errorf("cannot determine %s availability from /proc/self/status: %w", name, err)
	}
	if capabilities&(uint64(1)<<bit) == 0 {
		return fmt.Errorf("%s is missing; %s. Run the daemon/test as root with %s granted", name, consequence, name)
	}
	return nil
}

func effectiveCapabilities() (uint64, error) {
	contents, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		value, found := strings.CutPrefix(line, "CapEff:\t")
		if !found {
			continue
		}
		return strconv.ParseUint(strings.TrimSpace(value), 16, 64)
	}
	return 0, fmt.Errorf("capability effective-set field is absent")
}
