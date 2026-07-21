package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Service struct {
	discordWebhook string
	slackWebhook   string
	email          string
	client         *http.Client
}

func New(discordWebhook, slackWebhook, email string) *Service {
	return &Service{
		discordWebhook: strings.TrimSpace(discordWebhook),
		slackWebhook:   strings.TrimSpace(slackWebhook),
		email:          strings.TrimSpace(email),
		client:         &http.Client{Timeout: 10 * time.Second},
	}
}

// Validate rejects alert settings that the service cannot deliver safely.
func (s *Service) Validate() error {
	if s.email != "" {
		return fmt.Errorf("email alerts require SMTP configuration, which is not available")
	}
	for name, webhook := range map[string]string{
		"discord": s.discordWebhook,
		"slack":   s.slackWebhook,
	} {
		if webhook == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(webhook)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("%s webhook must be a valid HTTPS URL", name)
		}
	}
	return nil
}

func (s *Service) Send(message string) error {
	return s.SendContext(context.Background(), message)
}

// SendContext delivers configured webhooks and cancels in-flight requests
// when the owning runtime is shutting down.
func (s *Service) SendContext(ctx context.Context, message string) error {
	if ctx == nil {
		return fmt.Errorf("alert context is required")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	if s.discordWebhook != "" {
		if err := s.post(ctx, s.discordWebhook, map[string]string{"content": message}); err != nil {
			return fmt.Errorf("send Discord alert: %w", err)
		}
	}
	if s.slackWebhook != "" {
		if err := s.post(ctx, s.slackWebhook, map[string]string{"text": message}); err != nil {
			return fmt.Errorf("send Slack alert: %w", err)
		}
	}
	return nil
}

func (s *Service) post(ctx context.Context, webhook string, payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}
