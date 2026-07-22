package slack

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
	TimeoutMillis int    `json:"timeout_millis,omitempty"`
}
type Provider struct{ client *httptransport.Client }

func New(timeout time.Duration) *Provider { return &Provider{client: httptransport.New(timeout)} }
func (p *Provider) Validate(ctx context.Context, raw json.RawMessage) error {
	_, err := decode(raw)
	if err != nil {
		return err
	}
	result := p.Test(ctx, raw)
	if result.Success {
		return nil
	}
	return result.Error
}
func (p *Provider) Send(ctx context.Context, raw json.RawMessage, n alerts.Notification) alerts.DeliveryResult {
	cfg, err := decode(raw)
	if err != nil {
		return alerts.DeliveryResult{Error: err}
	}
	payload := map[string]any{"text": "DigitDojo Shield alert", "blocks": []map[string]any{{"type": "header", "text": map[string]string{"type": "plain_text", "text": "DigitDojo Shield Alert"}}, {"type": "section", "text": map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*Event:* %s\n*Severity:* %s\n%s", n.Event, n.Severity, n.Message)}}, {"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": time.Now().UTC().Format(time.RFC3339)}}}}}
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
	result := p.Test(ctx, raw)
	health := alerts.Health{CheckedAt: time.Now().UTC(), Status: alerts.Healthy}
	if !result.Success {
		health.Status = alerts.Unreachable
		if result.Error != nil {
			health.Error = result.Error.Error()
		}
	}
	return health
}
func (p *Provider) Close() error { return nil }
func decode(raw json.RawMessage) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	parsed, err := url.ParseRequestURI(cfg.WebhookURL)
	if err != nil || parsed.Scheme != "https" || !strings.HasSuffix(parsed.Host, "hooks.slack.com") || !strings.HasPrefix(parsed.Path, "/services/") {
		return cfg, fmt.Errorf("Slack webhook must be an HTTPS hooks.slack.com/services URL")
	}
	return cfg, nil
}

var _ alerts.Transport = (*Provider)(nil)
