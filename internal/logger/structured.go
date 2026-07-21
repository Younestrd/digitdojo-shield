package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StructuredLogger writes JSON logs to stdout or a file.
type StructuredLogger struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	jsonOut bool
	closed  bool
}

// NewStructuredLogger creates a logger that can write JSON or plaintext entries.
func NewStructuredLogger(path string, jsonOut bool) (*StructuredLogger, error) {
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, err
		}
		return &StructuredLogger{path: path, file: file, jsonOut: jsonOut}, nil
	}
	return &StructuredLogger{jsonOut: jsonOut}, nil
}

// Info emits an informational entry.
func (l *StructuredLogger) Info(msg string, fields map[string]string) {
	l.write("INFO", msg, fields)
}

// Warn emits a warning entry.
func (l *StructuredLogger) Warn(msg string, fields map[string]string) {
	l.write("WARN", msg, fields)
}

// Error emits an error entry.
func (l *StructuredLogger) Error(msg string, fields map[string]string) {
	l.write("ERROR", msg, fields)
}

// Debug emits a debug entry.
func (l *StructuredLogger) Debug(msg string, fields map[string]string) {
	l.write("DEBUG", msg, fields)
}

func (l *StructuredLogger) write(level, msg string, fields map[string]string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	payload := map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339), "level": level, "message": msg}
	for k, v := range fields {
		if k == "timestamp" || k == "level" || k == "message" {
			continue
		}
		payload[k] = v
	}
	if l.jsonOut {
		data, _ := json.Marshal(payload)
		if l.file != nil {
			_, _ = l.file.Write(append(data, '\n'))
			return
		}
		fmt.Fprintln(os.Stdout, string(data))
		return
	}
	if l.file != nil {
		_, _ = fmt.Fprintf(l.file, "[%s] %s %v\n", level, msg, fields)
		return
	}
	fmt.Fprintf(os.Stdout, "[%s] %s %v\n", level, msg, fields)
}

// Close flushes and closes the logger's file resource.
func (l *StructuredLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.file == nil {
		return nil
	}
	if err := l.file.Sync(); err != nil {
		_ = l.file.Close()
		return err
	}
	return l.file.Close()
}
