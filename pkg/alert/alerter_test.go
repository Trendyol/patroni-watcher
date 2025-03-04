package alert

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/trendyol/patroni-watcher/pkg/config"
	"github.com/trendyol/patroni-watcher/pkg/models"
)

func TestSendAlerts(t *testing.T) {
	// Create test alerts
	alerts := []models.AlertEvent{
		{
			ClusterName:     "test-cluster",
			ClusterURL:      "http://test-cluster:8008",
			Timestamp:       time.Now(),
			RuleName:        "test-rule",
			RuleDescription: "Test rule description",
			Severity:        "critical",
			Message:         "Test alert message",
			Value:           "actual",
			ExpectedValue:   "expected",
		},
	}

	// Create test config with all channels disabled
	cfg := config.AlertsConfig{
		Slack: config.SlackConfig{
			Enabled: false,
		},
		Email: config.EmailConfig{
			Enabled: false,
		},
		Webhook: config.WebhookConfig{
			Enabled: false,
		},
		Telegram: config.TelegramConfig{
			Enabled: false,
		},
	}

	// Create alerter with disabled config
	alerter := NewAlerter(cfg)

	// This should not panic or cause errors since all channels are disabled
	alerter.SendAlerts(alerts)
	// No assertions needed as we're just testing that it doesn't panic
}

func TestSendSlackAlert(t *testing.T) {
	// Create test server that will record the request
	var receivedPayload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(payload)
		receivedPayload = payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create test alert
	alert := models.AlertEvent{
		ClusterName:     "test-cluster",
		ClusterURL:      "http://test-cluster:8008",
		Timestamp:       time.Now(),
		RuleName:        "test-rule",
		RuleDescription: "Test rule description",
		Severity:        "critical",
		Message:         "Test alert message",
		Value:           "actual",
		ExpectedValue:   "expected",
	}

	// Create test config with Slack enabled
	cfg := config.AlertsConfig{
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: server.URL,
			Channel:    "test-channel",
		},
	}

	// Create alerter with the test config
	alerter := NewAlerter(cfg)

	// Test sending Slack alert
	err := alerter.sendSlackAlert(alert)
	assert.NoError(t, err)
	assert.NotEmpty(t, receivedPayload)
}

func TestSendWebhookAlert(t *testing.T) {
	// Create test server that will record the request
	var receivedPayload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(payload)
		receivedPayload = payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create test alert
	alert := models.AlertEvent{
		ClusterName:     "test-cluster",
		ClusterURL:      "http://test-cluster:8008",
		Timestamp:       time.Now(),
		RuleName:        "test-rule",
		RuleDescription: "Test rule description",
		Severity:        "critical",
		Message:         "Test alert message",
		Value:           "actual",
		ExpectedValue:   "expected",
	}

	// Create test config with Webhook enabled
	cfg := config.AlertsConfig{
		Webhook: config.WebhookConfig{
			Enabled: true,
			URL:     server.URL,
		},
	}

	// Create alerter with the test config
	alerter := NewAlerter(cfg)

	// Test sending Webhook alert
	err := alerter.sendWebhookAlert(alert)
	assert.NoError(t, err)
	assert.NotEmpty(t, receivedPayload)
}

// HTTPClient interface for easier testing
type HTTPClient interface {
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

// MockHTTPClient is a mock implementation of the HTTP client
type MockHTTPClient struct {
	mock.Mock
}

// Post is a mocked implementation of http.Post
func (m *MockHTTPClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	args := m.Called(url, contentType, body)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestSendTelegramAlert(t *testing.T) {
	// Skip this test as it requires modifying global http.Post function
	// which isn't easily doable without additional test helpers or interfaces
	t.Skip("Skipping Telegram test as it requires mocking the global http.Post function")
}

func TestSendAlert(t *testing.T) {
	// Create a set of test servers for each alert channel
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookServer.Close()

	// Create test alert
	alert := models.AlertEvent{
		ClusterName:     "test-cluster",
		ClusterURL:      "http://test-cluster:8008",
		Timestamp:       time.Now(),
		RuleName:        "test-rule",
		RuleDescription: "Test rule description",
		Severity:        "critical",
		Message:         "Test alert message",
		Value:           "actual",
		ExpectedValue:   "expected",
	}

	// Create test config with multiple channels enabled
	cfg := config.AlertsConfig{
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: slackServer.URL,
			Channel:    "test-channel",
		},
		Email: config.EmailConfig{
			Enabled: false, // SMTP testing is complex, so we keep it disabled
		},
		Webhook: config.WebhookConfig{
			Enabled: true,
			URL:     webhookServer.URL,
		},
		Telegram: config.TelegramConfig{
			Enabled: false, // Keeping it simple for this test
		},
	}

	// Create alerter with the test config
	alerter := NewAlerter(cfg)

	// Test the sendAlert method (which should call the enabled channel methods)
	alerter.sendAlert(alert)
	// No assertions needed here as we're just testing that it doesn't panic
	// The specific channel tests above verify the actual sending logic
}

func TestGetSeverityColor(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "#FF0000"},
		{"high", "#FFA500"},
		{"medium", "#FFFF00"},
		{"low", "#00FF00"},
		{"unknown", "#808080"},
		{"CRITICAL", "#FF0000"}, // Test case insensitivity
	}

	for _, test := range tests {
		t.Run(test.severity, func(t *testing.T) {
			color := getSeverityColor(test.severity)
			assert.Equal(t, test.expected, color)
		})
	}
}
