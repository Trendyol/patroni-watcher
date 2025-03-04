package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	t.Run("Valid Config File", func(t *testing.T) {
		// Create a test config file
		configContent := `
log_level: debug
check_interval: 30s
clusters:
  - name: patroni-cluster-1
    endpoint: "http://localhost:8008"
    username: "admin"
    password: "admin"
rules:
  - name: cluster-member-count
    description: "Checks the number of cluster members"
    check: "json"
    path: "$.members.length"
    operator: ">="
    value: 3
    severity: "critical"
alerts:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"
    channel: "#alerts"
  email:
    enabled: false
    smtp_host: "smtp.example.com"
    smtp_port: 587
    username: "user"
    password: "pass"
    from: "alerts@example.com"
    to:
      - "admin@example.com"
  webhook:
    enabled: false
    url: "https://example.com/webhook"
  telegram:
    enabled: false
    bot_token: "token123"
    chat_id: "123456789"
`
		configPath := filepath.Join(tempDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		assert.NoError(t, err)

		// Specify the directory containing the config file
		config, err := LoadConfig(tempDir)
		assert.NoError(t, err)
		assert.NotNil(t, config)

		// Validate config fields
		assert.Equal(t, "debug", config.LogLevel)
		assert.Equal(t, 30*time.Second, config.Interval)

		// Validate cluster
		assert.Len(t, config.Clusters, 1)
		assert.Equal(t, "patroni-cluster-1", config.Clusters[0].Name)
		assert.Equal(t, "http://localhost:8008", config.Clusters[0].Endpoint)
		assert.Equal(t, "admin", config.Clusters[0].Username)
		assert.Equal(t, "admin", config.Clusters[0].Password)

		// Validate rules
		assert.Len(t, config.Rules, 1)
		assert.Equal(t, "cluster-member-count", config.Rules[0].Name)
		assert.Equal(t, "Checks the number of cluster members", config.Rules[0].Description)
		assert.Equal(t, "json", config.Rules[0].Check)
		assert.Equal(t, "$.members.length", config.Rules[0].Path)
		assert.Equal(t, ">=", config.Rules[0].Operator)
		assert.Equal(t, 3, config.Rules[0].Value)
		assert.Equal(t, "critical", config.Rules[0].Severity)

		// Validate alerts
		assert.True(t, config.Alerts.Slack.Enabled)
		assert.Equal(t, "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ", config.Alerts.Slack.WebhookURL)
		assert.Equal(t, "#alerts", config.Alerts.Slack.Channel)

		assert.False(t, config.Alerts.Email.Enabled)
		assert.Equal(t, "smtp.example.com", config.Alerts.Email.SMTPHost)
	})

	t.Run("Default Values", func(t *testing.T) {
		// Config file with minimal values
		configContent := `
clusters:
  - name: test-cluster
    endpoint: "http://localhost:8008"
    username: "admin"
    password: "admin"
`
		configPath := filepath.Join(tempDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		assert.NoError(t, err)

		config, err := LoadConfig(tempDir)
		assert.NoError(t, err)
		assert.NotNil(t, config)

		// Check default values
		assert.Equal(t, "info", config.LogLevel)
		assert.Equal(t, 1*time.Minute, config.Interval)
	})

	t.Run("Invalid Config File", func(t *testing.T) {
		// Create a file with invalid YAML
		configContent := `
log_level: debug
check_interval: 30s
clusters:
  - name: test-cluster
    endpoint: "http://localhost:8008"
    username: "admin"
    password: "admin"
  invalid_yaml_line
`
		configPath := filepath.Join(tempDir, "config.yaml")
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		assert.NoError(t, err)

		config, err := LoadConfig(tempDir)
		assert.Error(t, err)
		assert.Nil(t, config)
	})

	t.Run("Non-existent Config File", func(t *testing.T) {
		// Specify a non-existent directory
		config, err := LoadConfig("/path/does/not/exist")
		assert.Error(t, err)
		assert.Nil(t, config)
	})
}
