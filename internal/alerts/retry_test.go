package alerts

import (
	"context"
	"errors"
	"testing"
)

type retryError struct{}

func (retryError) Error() string   { return "retry" }
func (retryError) Temporary() bool { return true }
func TestRetryRetriesTemporaryFailure(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryPolicy{Attempts: 3, InitialBackoffMillis: 1}, func(context.Context) error {
		calls++
		if calls < 3 {
			return retryError{}
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
func TestRetryStopsPermanentFailure(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), RetryPolicy{Attempts: 3, InitialBackoffMillis: 1}, func(context.Context) error { calls++; return errors.New("permanent") })
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
