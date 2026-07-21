package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"digitdojo-shield/internal/blacklist"
	"digitdojo-shield/internal/config"
	"digitdojo-shield/internal/whitelist"
)

func TestInjectedRuntimeStateAndEnforcementFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.API.Enabled = true
	cfg.API.Token = "secret"
	blacklistManager := blacklist.NewManager()
	whitelistManager := whitelist.NewManager()
	if err := blacklistManager.Add(cfg, "8.8.8.8"); err != nil {
		t.Fatalf("seed blacklist: %v", err)
	}
	server, err := NewServerWithDependencies(cfg, Dependencies{
		Blacklist: blacklistManager,
		Whitelist: whitelistManager,
		Stats: func() RuntimeStats {
			return RuntimeStats{Blocked: blacklistManager.ListLen(), AttackStatus: "quiet"}
		},
		AddBlacklist:    func(string) error { return ErrEnforcementUnavailable },
		AddWhitelist:    func(string) error { return ErrEnforcementUnavailable },
		RemoveBlacklist: func(string) error { return ErrEnforcementUnavailable },
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/blacklist", bytes.NewBufferString(`{"ip":"1.1.1.1"}`))
	request.Header.Set("X-API-Key", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected service unavailable, got %d", response.Code)
	}
	statsRequest := httptest.NewRequest(http.MethodGet, "/stats", nil)
	statsRequest.Header.Set("X-API-Key", "secret")
	statsResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(statsResponse, statsRequest)
	if statsResponse.Code != http.StatusOK || !bytes.Contains(statsResponse.Body.Bytes(), []byte(`"blocked":1`)) {
		t.Fatalf("API did not read shared state: code=%d body=%s", statsResponse.Code, statsResponse.Body.String())
	}
}
