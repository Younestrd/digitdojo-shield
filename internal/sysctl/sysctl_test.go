package sysctl

import (
    "os"
    "path/filepath"
    "testing"
)

func TestReadAllKernelParams(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "sysctl.conf")
    data := []byte("net.ipv4.tcp_syncookies = 1\n# comment\nnet.core.somaxconn = 4096\n")
    if err := os.WriteFile(path, data, 0o644); err != nil {
        t.Fatalf("write file: %v", err)
    }

    params, err := ReadAllKernelParams(path)
    if err != nil {
        t.Fatalf("read params: %v", err)
    }
    if len(params) != 2 {
        t.Fatalf("expected 2 params, got %d", len(params))
    }
}

func TestParseKernelBool(t *testing.T) {
    if !ParseKernelBool("1") {
        t.Fatalf("expected true")
    }
}
