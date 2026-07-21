package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"digitdojo-shield/internal/config"
)

func TestConcurrentRequests(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.API.Enabled = true
	cfg.API.Token = "secret"
	srv := NewServer(cfg)
	handler := srv.Handler()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/stats", nil)
			req.RemoteAddr = "192.0.2.1:12345"
			req.Header.Set("X-API-Key", "secret")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("expected status ok, got %d", rr.Code)
			}
		}()
	}
	wg.Wait()
}
