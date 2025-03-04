package config

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	LogLevel string        `mapstructure:"log_level"`
	Clusters []Cluster     `mapstructure:"clusters"`
	Rules    []Rule        `mapstructure:"rules"`
	Alerts   AlertsConfig  `mapstructure:"alerts"`
	Interval time.Duration `mapstructure:"check_interval"`
}

type Cluster struct {
	Name     string `mapstructure:"name"`
	Endpoint string `mapstructure:"endpoint"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type Rule struct {
	Name        string      `mapstructure:"name"`
	Description string      `mapstructure:"description"`
	Check       string      `mapstructure:"check"`
	Path        string      `mapstructure:"path"`
	Operator    string      `mapstructure:"operator"`
	Value       interface{} `mapstructure:"value"`
	Severity    string      `mapstructure:"severity"`
}

type AlertsConfig struct {
	Slack    SlackConfig    `mapstructure:"slack"`
	Email    EmailConfig    `mapstructure:"email"`
	Webhook  WebhookConfig  `mapstructure:"webhook"`
	Telegram TelegramConfig `mapstructure:"telegram"`
}

type SlackConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	WebhookURL string `mapstructure:"webhook_url"`
	Channel    string `mapstructure:"channel"`
}

type EmailConfig struct {
	Enabled  bool     `mapstructure:"enabled"`
	SMTPHost string   `mapstructure:"smtp_host"`
	SMTPPort int      `mapstructure:"smtp_port"`
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
	From     string   `mapstructure:"from"`
	To       []string `mapstructure:"to"`
}

type WebhookConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	URL     string `mapstructure:"url"`
}

type TelegramConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	BotToken string `mapstructure:"bot_token"`
	ChatID   string `mapstructure:"chat_id"`
}

func LoadConfig(path string) (*Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config file not read: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("config not parsed: %w", err)
	}

	if config.LogLevel == "" {
		config.LogLevel = "info"
	}

	if config.Interval == 0 {
		config.Interval = 1 * time.Minute
	}

	log.Info().Msg("Config loaded successfully")
	return &config, nil
}
