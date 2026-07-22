package logger

import "testing"

func TestStructuredLoggerWritesMessage(t *testing.T) {
	logger, err := NewStructuredLogger("", true)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	logger.Info("hello", map[string]string{"component": "test"})
}
