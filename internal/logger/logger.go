package logger

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "sync"
)

type Logger struct {
    mu      sync.Mutex
    path    string
    maxSize int64
    file    *os.File
}

func New(path string) (*Logger, error) {
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
        return nil, err
    }
    file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
    if err != nil {
        return nil, err
    }
    return &Logger{path: path, maxSize: 10 * 1024 * 1024, file: file}, nil
}

func (l *Logger) Infof(format string, args ...any) {
    l.write("INFO", format, args...)
}

func (l *Logger) Warnf(format string, args ...any) {
    l.write("WARN", format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
    l.write("ERROR", format, args...)
}

func (l *Logger) write(level, format string, args ...any) {
    l.mu.Lock()
    defer l.mu.Unlock()

    if l.file != nil {
        info, err := l.file.Stat()
        if err == nil && info.Size() >= l.maxSize {
            _ = l.file.Close()
            rotated := l.path + ".1"
            _ = os.Remove(rotated)
            _ = os.Rename(l.path, rotated)
            l.file, _ = os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
        }
    }

    msg := fmt.Sprintf("[%s] %s\n", strings.ToUpper(level), fmt.Sprintf(format, args...))
    _, _ = l.file.WriteString(msg)
}
