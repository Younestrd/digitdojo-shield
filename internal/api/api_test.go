package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"digitdojo-shield/internal/config"
)

func TestStatsEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.API.Enabled = true
	cfg.API.Token = "test-token"
	server := NewServer(cfg)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	req.Header.Set("X-API-Key", "test-token")
	rr := httptest.NewRecorder()

	server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %d", rr.Code)
	}
}

func TestServerListenerLifecycle(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.API.Enabled = true
	cfg.API.Token = "test-token"
	server := NewServer(cfg)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	errorsChannel, err := server.StartListener(listener)
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}

	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/stats", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("X-API-Key", "test-token")
	client := &http.Client{Timeout: time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request API: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case serveErr := <-errorsChannel:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("unexpected serve result: %v", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatalf("serve goroutine did not exit")
	}
}

func TestStatsEndpointRejectsMissingToken(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.API.Enabled = true
	cfg.API.Token = "test-token"
	server := NewServer(cfg)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rr := httptest.NewRecorder()

	server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized status, got %d", rr.Code)
	}
}
