package alerts

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
)

// Retry executes only retryable transport failures, respecting cancellation.
func Retry(ctx context.Context, policy RetryPolicy, operation func(context.Context) error) error {
	if operation == nil {
		return fmt.Errorf("retry operation is required")
	}
	if policy.Attempts < 1 {
		policy.Attempts = 1
	}
	if policy.InitialBackoffMillis < 1 {
		policy.InitialBackoffMillis = 100
	}
	var last error
	for attempt := 0; attempt < policy.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = operation(ctx)
		if last == nil || !Retryable(last) {
			return last
		}
		if attempt+1 == policy.Attempts {
			break
		}
		backoff := time.Duration(policy.InitialBackoffMillis*(1<<attempt)) * time.Millisecond
		jitter := time.Duration(rand.Int64N(int64(backoff/4 + 1)))
		timer := time.NewTimer(backoff + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

type TemporaryError interface {
	error
	Temporary() bool
}

func Retryable(err error) bool {
	var temporary TemporaryError
	return errors.As(err, &temporary) && temporary.Temporary()
}
