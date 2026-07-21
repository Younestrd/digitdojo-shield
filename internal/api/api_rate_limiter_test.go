package api

import (
    "testing"
)

func TestRateLimiterAllowsBurst(t *testing.T) {
    limiter := newRateLimiter(2, 2)
    if !limiter.allow("1.1.1.1") {
        t.Fatalf("expected first request to be allowed")
    }
    if !limiter.allow("1.1.1.1") {
        t.Fatalf("expected second request to be allowed")
    }
    if limiter.allow("1.1.1.1") {
        t.Fatalf("expected third request to be rate limited")
    }
}
