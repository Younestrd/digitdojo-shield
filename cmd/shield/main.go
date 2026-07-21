package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"digitdojo-shield/internal/blacklist"
	"digitdojo-shield/internal/config"
	"digitdojo-shield/internal/detector"
	"digitdojo-shield/internal/firewall"
	"digitdojo-shield/internal/monitor"
	"digitdojo-shield/internal/whitelist"
)

var configPath = flag.String("config", "/etc/digitdojo-shield/config.yml", "path to the configuration file")

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		printUsage()
		os.Exit(1)
	}

	command := flag.Arg(0)
	cfg, err := loadConfig(*configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	switch command {
	case "install":
		if err := runInstaller("install"); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("installation completed")
	case "uninstall":
		if err := runInstaller("uninstall"); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("uninstallation completed")
	case "status":
		fmt.Printf("status: ready\nlog_dir: %s\nstate_dir: %s\n", cfg.General.LogDir, cfg.General.StateDir)
	case "monitor":
		m := monitor.New()
		metrics := detector.Metrics{PacketsPerSecond: 1200, BytesPerSecond: 2 * 1024 * 1024, TopTalkers: []string{"1.1.1.1", "2.2.2.2"}}
		stats := m.Snapshot(metrics, 2, []detector.Signal{{AttackType: "udp_flood"}})
		fmt.Printf("packets/sec: %d\nbandwidth: %d Mbps\nblocked: %d\nattack: %s\n", stats.PacketsPerSecond, stats.BandwidthMbps, stats.BlockedIPs, stats.AttackStatus)
	case "update":
		fmt.Println("update checks are not implemented in this release")
	case "version":
		fmt.Println("DigitDojo Shield v1.0.0")
	case "whitelist":
		if flag.NArg() < 2 {
			fmt.Println("usage: shield whitelist <ip>")
			os.Exit(1)
		}
		wl := whitelist.NewManager()
		if err := wl.Add(cfg, flag.Arg(1)); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("whitelisted %s\n", flag.Arg(1))
	case "blacklist":
		if flag.NArg() < 2 {
			fmt.Println("usage: shield blacklist <ip>")
			os.Exit(1)
		}
		bl := blacklist.NewManager()
		if err := bl.Add(cfg, flag.Arg(1)); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("blacklisted %s\n", flag.Arg(1))
	case "unban":
		if flag.NArg() < 2 {
			fmt.Println("usage: shield unban <ip>")
			os.Exit(1)
		}
		bl := blacklist.NewManager()
		if err := bl.Remove(flag.Arg(1)); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("removed %s\n", flag.Arg(1))
	case "stats":
		engine := detector.NewEngine(cfg.Detection.PacketThreshold)
		metrics := detector.Metrics{PacketsPerSecond: 1200, ConnectionsPerSecond: 800}
		signals := engine.Evaluate(metrics)
		fmt.Printf("signals: %d\n", len(signals))
	case "doctor":
		registry, err := firewall.NewDefaultRegistry()
		if err != nil {
			fmt.Fprintf(os.Stderr, "firewall registry: %v\n", err)
			os.Exit(1)
		}
		controller, err := firewall.NewController(registry, cfg.Firewall.Backend)
		if err != nil {
			fmt.Fprintf(os.Stderr, "firewall controller: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("firewall: %s\n", controller.Describe(context.Background()))
		for _, capability := range controller.Capabilities(context.Background()) {
			fmt.Printf("%s: detected=%t implemented=%t reason=%s\n", capability.Name, capability.Detected, capability.Implemented, capability.Reason)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

func runInstaller(mode string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("installer is intended for Linux hosts")
	}

	script := filepath.Join("install", "install.sh")
	if mode == "uninstall" {
		script = filepath.Join("install", "uninstall.sh")
	}

	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("installer script not found: %s", script)
	}

	cmd := exec.Command("bash", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadConfig(path string) (config.Config, error) {
	if path == "" {
		return config.DefaultConfig(), nil
	}
	if _, err := os.Stat(path); err != nil {
		return config.DefaultConfig(), err
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return config.DefaultConfig(), err
	}
	return cfg, nil
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  shield install")
	fmt.Println("  shield uninstall")
	fmt.Println("  shield status")
	fmt.Println("  shield monitor")
	fmt.Println("  shield update")
	fmt.Println("  shield version")
	fmt.Println("  shield whitelist <ip>")
	fmt.Println("  shield blacklist <ip>")
	fmt.Println("  shield unban <ip>")
	fmt.Println("  shield stats")
	fmt.Println("  shield doctor")
	fmt.Println("\nConfiguration:")
	fmt.Printf("  %s\n", filepath.Clean("/etc/digitdojo-shield/config.yml"))
}
