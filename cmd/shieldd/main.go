package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"digitdojo-shield/internal/app"
	"digitdojo-shield/internal/config"
)

func main() {
	configPath := flag.String("config", "/etc/digitdojo-shield/config.yml", "path to the configuration file")
	flag.Parse()

	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "shieldd is supported only on Linux")
		os.Exit(1)
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "configuration path is required")
		os.Exit(1)
	}
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load configuration: %v\n", err)
		os.Exit(1)
	}
	manager, err := config.NewManager(*configPath, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize configuration manager: %v\n", err)
		os.Exit(1)
	}
	application, err := app.NewWithConfigManager(manager)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize runtime: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := application.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "runtime stopped with error: %v\n", err)
		os.Exit(1)
	}
}
