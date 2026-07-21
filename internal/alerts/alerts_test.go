package alerts

import "testing"

func TestValidateRejectsUnsupportedOrInsecureDestinations(t *testing.T) {
	tests := []struct {
		name    string
		service *Service
	}{
		{name: "email without SMTP", service: New("", "", "admin@example.com")},
		{name: "non-HTTPS Discord", service: New("http://example.com/webhook", "", "")},
		{name: "invalid Slack URL", service: New("", "://bad", "")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.service.Validate(); err == nil {
				t.Fatalf("expected validation failure")
			}
		})
	}
}

func TestValidateAcceptsHTTPSWebhooks(t *testing.T) {
	service := New("https://discord.example/webhook", "https://slack.example/webhook", "")
	if err := service.Validate(); err != nil {
		t.Fatalf("expected valid webhooks: %v", err)
	}
}
