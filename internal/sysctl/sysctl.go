package sysctl

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
)

// Parameter documents the safe sysctl values applied by the hardening engine.
type Parameter struct {
    Name  string
    Value string
    Why   string
}

// Manager applies and restores safe sysctl values.
type Manager struct {
    backupDir string
}

func NewManager(backupDir string) *Manager {
    if backupDir == "" {
        backupDir = "/var/backups/digitdojo-shield"
    }
    return &Manager{backupDir: backupDir}
}

func (m *Manager) Backup() ([]Parameter, error) {
    if err := os.MkdirAll(m.backupDir, 0o755); err != nil {
        return nil, err
    }
    params := []Parameter{
        {Name: "net.ipv4.tcp_syncookies", Value: "1", Why: "protect against SYN flood abuse"},
        {Name: "net.ipv4.conf.all.rp_filter", Value: "1", Why: "drop spoofed source packets"},
        {Name: "net.ipv4.conf.default.rp_filter", Value: "1", Why: "drop spoofed source packets by default"},
        {Name: "net.ipv4.conf.all.accept_redirects", Value: "0", Why: "disable ICMP redirects"},
        {Name: "net.ipv4.conf.default.accept_redirects", Value: "0", Why: "disable ICMP redirects by default"},
        {Name: "net.ipv4.conf.all.send_redirects", Value: "0", Why: "disable sending ICMP redirects"},
        {Name: "net.ipv4.conf.default.send_redirects", Value: "0", Why: "disable sending ICMP redirects by default"},
        {Name: "net.ipv4.tcp_max_syn_backlog", Value: "4096", Why: "increase SYN queue capacity"},
        {Name: "net.core.somaxconn", Value: "4096", Why: "increase listen backlog"},
        {Name: "net.core.netdev_max_backlog", Value: "16384", Why: "reduce packet drops on busy interfaces"},
    }

    for _, p := range params {
        current, err := readSysctl(p.Name)
        if err != nil {
            continue
        }
        path := filepath.Join(m.backupDir, strings.ReplaceAll(p.Name, ".", "_")+".bak")
        if err := os.WriteFile(path, []byte(current), 0o644); err != nil {
            return nil, err
        }
    }
    return params, nil
}

func (m *Manager) Apply(params []Parameter) error {
    for _, p := range params {
        if err := writeSysctl(p.Name, p.Value); err != nil {
            return err
        }
    }
    return nil
}

func (m *Manager) Restore() error {
    entries, err := os.ReadDir(m.backupDir)
    if err != nil {
        return err
    }
    for _, entry := range entries {
        if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bak") {
            continue
        }
        name := strings.ReplaceAll(strings.TrimSuffix(entry.Name(), ".bak"), "_", ".")
        data, err := os.ReadFile(filepath.Join(m.backupDir, entry.Name()))
        if err != nil {
            return err
        }
        if err := writeSysctl(name, strings.TrimSpace(string(data))); err != nil {
            return err
        }
    }
    return nil
}

func readSysctl(name string) (string, error) {
    out, err := exec.Command("sysctl", name).CombinedOutput()
    if err != nil {
        return "", err
    }
    fields := strings.Fields(string(out))
    if len(fields) < 2 {
        return "", fmt.Errorf("unexpected sysctl output")
    }
    return strings.TrimSpace(fields[len(fields)-1]), nil
}

func writeSysctl(name, value string) error {
    if name == "" || value == "" {
        return fmt.Errorf("sysctl name and value are required")
    }
    if _, err := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", name, value)).CombinedOutput(); err != nil {
        return err
    }
    return nil
}

func ParseKernelBool(value string) bool {
    v, err := strconv.ParseBool(value)
    if err == nil {
        return v
    }
    return false
}

func LoadCurrentValues(names []string) (map[string]string, error) {
    values := make(map[string]string, len(names))
    for _, name := range names {
        value, err := readSysctl(name)
        if err != nil {
            return nil, err
        }
        values[name] = value
    }
    return values, nil
}

func ReadAllKernelParams(path string) ([]string, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var params []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        if strings.Contains(line, "=") {
            params = append(params, strings.SplitN(line, "=", 2)[0])
        }
    }
    return params, scanner.Err()
}
