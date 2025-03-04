package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/trendyol/patroni-watcher/pkg/alert"
	"github.com/trendyol/patroni-watcher/pkg/api"
	"github.com/trendyol/patroni-watcher/pkg/config"
	"github.com/trendyol/patroni-watcher/pkg/rules"
)

func main() {
	configPath := flag.String("config", "./config", "Config file path")
	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	// Load config
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Config load failed")
	}

	// Set log level
	logLevel, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid log level, using 'info'")
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	// Create API client
	client := api.NewClient()

	// Create rule evaluator
	evaluator := rules.NewEvaluator(cfg.Rules)

	// Create alert manager
	alerter := alert.NewAlerter(cfg.Alerts)

	// Create signal handler
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Create ticker
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	log.Info().
		Int("cluster_count", len(cfg.Clusters)).
		Int("rule_count", len(cfg.Rules)).
		Dur("interval", cfg.Interval).
		Msg("Patroni Alarm System started")

	// First check immediately
	checkClusters(client, evaluator, alerter, cfg.Clusters)

	// Main loop
	for {
		select {
		case <-ticker.C:
			// Periodic check
			checkClusters(client, evaluator, alerter, cfg.Clusters)
		case sig := <-sigs:
			// Clean exit on signal
			log.Info().
				Str("signal", sig.String()).
				Msg("Signal received, shutting down")
			return
		}
	}
}

// checkClusters, all clusters are checked
func checkClusters(client *api.Client, evaluator *rules.Evaluator, alerter *alert.Alerter, clusters []config.Cluster) {
	for _, cluster := range clusters {
		log.Debug().
			Str("cluster", cluster.Name).
			Str("endpoint", cluster.Endpoint).
			Msg("Checking cluster")

		// Get cluster status
		resp, err := client.GetClusterStatus(cluster)
		if err != nil {
			log.Error().
				Err(err).
				Str("cluster", cluster.Name).
				Str("endpoint", cluster.Endpoint).
				Msg("Cluster status not retrieved")
			continue
		}

		// Evaluate rules
		alerts := evaluator.EvaluateRules(cluster.Name, cluster.Endpoint, resp)
		if len(alerts) > 0 {
			log.Info().
				Str("cluster", cluster.Name).
				Int("alert_count", len(alerts)).
				Msg("Alerts triggered")

			// Send alerts
			alerter.SendAlerts(alerts)
		} else {
			log.Debug().
				Str("cluster", cluster.Name).
				Msg("No rules triggered")
		}
	}
}
