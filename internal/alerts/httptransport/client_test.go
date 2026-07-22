package httptransport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostJSONClassifiesRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer server.Close()
	_, _, err := New(time.Second).PostJSON(context.Background(), server.URL, nil, map[string]string{"x": "y"})
	typed, ok := err.(*Error)
	if !ok || typed.Class != RateLimited || !typed.Temporary() {
		t.Fatalf("err=%v", err)
	}
}
