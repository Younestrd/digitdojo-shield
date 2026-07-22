package discord

import (
	"context"
	"digitdojo-shield/internal/alerts"
	"digitdojo-shield/internal/alerts/httptransport"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	WebhookURL    string `json:"webhook_url"`
	Username      string `json:"username,omitempty"`
	Footer        string `json:"footer,omitempty"`
	TimeoutMillis int    `json:"timeout_millis,omitempty"`
}
type Provider struct{ client *httptransport.Client }

func New(timeout time.Duration) *Provider { return &Provider{client: httptransport.New(timeout)} }
func (p *Provider) Validate(ctx context.Context, raw json.RawMessage) error {
	cfg, err := decode(raw)
	if err != nil {
		return err
	}
	_, _, err = p.client.PostJSON(ctx, cfg.WebhookURL, nil, map[string]any{"content": "DigitDojo Shield validation"})
	return err
}
func (p *Provider) Send(ctx context.Context, raw json.RawMessage, notification alerts.Notification) alerts.DeliveryResult {
	cfg, err := decode(raw)
	if err != nil {
		return alerts.DeliveryResult{Error: err}
	}
	color := map[string]int{"INFO": 3447003, "WARN": 15844367, "HIGH": 15105570, "CRITICAL": 15158332}[strings.ToUpper(notification.Severity)]
	payload := map[string]any{"username": cfg.Username, "embeds": []map[string]any{{"title": "DigitDojo Shield Alert", "description": notification.Message, "color": color, "timestamp": time.Now().UTC().Format(time.RFC3339), "footer": map[string]string{"text": cfg.Footer}, "fields": []map[string]any{{"name": "Event", "value": notification.Event, "inline": true}, {"name": "Severity", "value": notification.Severity, "inline": true}}}}}
	status, _, err := p.client.PostJSON(ctx, cfg.WebhookURL, nil, payload)
	if err != nil {
		result := alerts.DeliveryResult{ResponseCode: status, Error: err}
		if typed, ok := err.(*httptransport.Error); ok {
			result.Retryable = typed.Temporary()
		}
		return result
	}
	return alerts.DeliveryResult{Success: true, ResponseCode: status}
}
func (p *Provider) Test(ctx context.Context, raw json.RawMessage) alerts.DeliveryResult {
	return p.Send(ctx, raw, alerts.Notification{Event: "test", Severity: "INFO", Message: "DigitDojo Shield test notification"})
}
func (p *Provider) Health(ctx context.Context, raw json.RawMessage) alerts.Health {
	start := time.Now()
	result := p.Test(ctx, raw)
	health := alerts.Health{CheckedAt: time.Now().UTC()}
	if result.Success {
		health.Status = alerts.Healthy
	} else {
		health.Status = alerts.Unreachable
		if result.Error != nil {
			health.Error = result.Error.Error()
		}
	}
	_ = start
	return health
}
func (p *Provider) Close() error { return nil }
func decode(raw json.RawMessage) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	parsed, err := url.ParseRequestURI(cfg.WebhookURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "discord.com" && !strings.HasSuffix(parsed.Host, "discord.com") {
		return cfg, fmt.Errorf("discord webhook must be an HTTPS discord.com URL")
	}
	if !strings.HasPrefix(parsed.Path, "/api/webhooks/") {
		return cfg, fmt.Errorf("invalid Discord webhook path")
	}
	return cfg, nil
}

var _ alerts.Transport = (*Provider)(nil)
