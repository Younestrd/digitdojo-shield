package api

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"digitdojo-shield/internal/blacklist"
	"digitdojo-shield/internal/config"
	"digitdojo-shield/internal/events"
	"digitdojo-shield/internal/whitelist"
)

func TestEventsEndpointStreamsPublishedEvent(t *testing.T) {
	cfg := config.DefaultConfig()
	bus := events.NewBus()
	server, err := NewServerWithDependencies(cfg, Dependencies{
		Blacklist: blacklist.NewManager(), Whitelist: whitelist.NewManager(),
		AddBlacklist: func(string) error { return nil }, AddWhitelist: func(string) error { return nil }, RemoveBlacklist: func(string) error { return nil },
		Subscribe: bus.Subscribe,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	response, err := http.Get(httpServer.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	bus.Publish(events.Event{Type: "AttackDetected", Payload: map[string]string{"signals": "1"}})
	scanner := bufio.NewScanner(response.Body)
	deadline := time.After(2 * time.Second)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), `"type":"AttackDetected"`) {
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for streamed event")
		default:
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("event stream ended before attack event")
}

func TestEventsEndpointRejectsWrongMethod(t *testing.T) {
	server := NewServer(config.DefaultConfig())
	request := httptest.NewRequest(http.MethodPost, "/events", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", response.Code)
	}
	if strings.TrimSpace(response.Body.String()) != "" {
		t.Fatalf("unexpected body %q", response.Body.String())
	}
}
