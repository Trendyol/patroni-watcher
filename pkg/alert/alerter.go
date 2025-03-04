package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/trendyol/patroni-watcher/pkg/config"
	"github.com/trendyol/patroni-watcher/pkg/models"
)

type Alerter struct {
	config config.AlertsConfig
}

func NewAlerter(config config.AlertsConfig) *Alerter {
	return &Alerter{
		config: config,
	}
}

func (a *Alerter) SendAlerts(alerts []models.AlertEvent) {
	for _, alert := range alerts {
		a.sendAlert(alert)
	}
}

func (a *Alerter) sendAlert(alert models.AlertEvent) {
	log.Info().
		Str("cluster", alert.ClusterName).
		Str("rule", alert.RuleName).
		Str("severity", alert.Severity).
		Msg("Sending alert")

	// Slack
	if a.config.Slack.Enabled {
		if err := a.sendSlackAlert(alert); err != nil {
			log.Error().Err(err).Msg("Slack alert not sent")
		}
	}

	// Email
	if a.config.Email.Enabled {
		if err := a.sendEmailAlert(alert); err != nil {
			log.Error().Err(err).Msg("Email alert not sent")
		}
	}

	// Webhook
	if a.config.Webhook.Enabled {
		if err := a.sendWebhookAlert(alert); err != nil {
			log.Error().Err(err).Msg("Webhook alert not sent")
		}
	}

	// Telegram
	if a.config.Telegram.Enabled {
		if err := a.sendTelegramAlert(alert); err != nil {
			log.Error().Err(err).Msg("Telegram alert not sent")
		}
	}
}

// sendSlackAlert, Slack alert sends
func (a *Alerter) sendSlackAlert(alert models.AlertEvent) error {
	// Create Slack message
	payload := map[string]interface{}{
		"channel": a.config.Slack.Channel,
		"text":    fmt.Sprintf("*Patroni Alarm:* %s", alert.RuleName),
		"attachments": []map[string]interface{}{
			{
				"color": getSeverityColor(alert.Severity),
				"fields": []map[string]interface{}{
					{
						"title": "Cluster",
						"value": alert.ClusterName,
						"short": true,
					},
					{
						"title": "Severity",
						"value": alert.Severity,
						"short": true,
					},
					{
						"title": "Rule",
						"value": alert.RuleName,
						"short": false,
					},
					{
						"title": "Description",
						"value": alert.RuleDescription,
						"short": false,
					},
					{
						"title": "Message",
						"value": alert.Message,
						"short": false,
					},
				},
				"footer": "Patroni Alarm System",
				"ts":     alert.Timestamp.Unix(),
			},
		},
	}

	// Convert to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("JSON conversion error: %w", err)
	}

	// Send HTTP request
	resp, err := http.Post(a.config.Slack.WebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	// İstek başarısız ise hata döndür
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook error: %s", resp.Status)
	}

	log.Info().Msg("Slack alert sent")
	return nil
}

// sendEmailAlert, e-posta alarmı gönderir
func (a *Alerter) sendEmailAlert(alert models.AlertEvent) error {
	// Create email subject
	subject := fmt.Sprintf("Patroni Alarm: %s - %s", alert.ClusterName, alert.RuleName)

	// Create email body
	body := fmt.Sprintf(`
Patroni Alarm System

Cluster: %s
Severity: %s
Rule: %s
Description: %s
Message: %s
Time: %s

Patroni Alarm System
`, alert.ClusterName, alert.Severity, alert.RuleName, alert.RuleDescription, alert.Message, alert.Timestamp.Format("2006-01-02 15:04:05"))

	// Add MIME headers
	headers := fmt.Sprintf("From: %s\r\n", a.config.Email.From)
	headers += fmt.Sprintf("To: %s\r\n", strings.Join(a.config.Email.To, ", "))
	headers += fmt.Sprintf("Subject: %s\r\n", subject)
	headers += "MIME-Version: 1.0\r\n"
	headers += "Content-Type: text/plain; charset=utf-8\r\n\r\n"

	// Create message
	message := headers + body

	// Connect to SMTP server
	auth := smtp.PlainAuth("", a.config.Email.Username, a.config.Email.Password, a.config.Email.SMTPHost)
	smtpAddr := fmt.Sprintf("%s:%d", a.config.Email.SMTPHost, a.config.Email.SMTPPort)

	// Send email
	if err := smtp.SendMail(smtpAddr, auth, a.config.Email.From, a.config.Email.To, []byte(message)); err != nil {
		return fmt.Errorf("SMTP error: %w", err)
	}

	log.Info().Msg("Email alert sent")
	return nil
}

func (a *Alerter) sendWebhookAlert(alert models.AlertEvent) error {
	// Create payload
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("JSON conversion error: %w", err)
	}

	// Send HTTP request
	resp, err := http.Post(a.config.Webhook.URL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	// If request fails, return error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook error: %s", resp.Status)
	}

	log.Info().Msg("Webhook alert sent")
	return nil
}

func (a *Alerter) sendTelegramAlert(alert models.AlertEvent) error {
	message := fmt.Sprintf(`
*Patroni Alarm*
*Cluster:* %s
*Severity:* %s
*Rule:* %s
*Description:* %s
*Message:* %s
*Time:* %s
`, alert.ClusterName, alert.Severity, alert.RuleName, alert.RuleDescription, alert.Message, alert.Timestamp.Format("2006-01-02 15:04:05"))

	data := map[string]interface{}{
		"chat_id":    a.config.Telegram.ChatID,
		"text":       message,
		"parse_mode": "Markdown",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON conversion error: %w", err)
	}

	// Create Telegram API URL
	telegramAPI := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", a.config.Telegram.BotToken)

	// Send HTTP request
	resp, err := http.Post(telegramAPI, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	// If request fails, return error
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram api error: %s", resp.Status)
	}

	log.Info().Msg("Telegram alert sent")
	return nil
}

func getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "#FF0000" // Red
	case "high":
		return "#FFA500" // Orange
	case "medium":
		return "#FFFF00" // Yellow
	case "low":
		return "#00FF00" // Green
	default:
		return "#808080" // Gray
	}
}
