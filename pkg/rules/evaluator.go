package rules

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/trendyol/patroni-watcher/pkg/config"
	"github.com/trendyol/patroni-watcher/pkg/models"
)

type Evaluator struct {
	rules []config.Rule
}

func NewEvaluator(rules []config.Rule) *Evaluator {
	return &Evaluator{
		rules: rules,
	}
}

func (e *Evaluator) EvaluateRules(clusterName, clusterURL string, resp *models.PatroniResponse) []models.AlertEvent {
	var alerts []models.AlertEvent

	for _, rule := range e.rules {
		triggered, value, expectedValue, err := e.evaluateRule(rule, resp)
		if err != nil {
			log.Error().Err(err).
				Str("cluster", clusterName).
				Str("rule", rule.Name).
				Msg("Error evaluating rule")
			continue
		}

		if !triggered {
			alert := models.AlertEvent{
				ClusterName:     clusterName,
				ClusterURL:      clusterURL,
				Timestamp:       time.Now(),
				RuleName:        rule.Name,
				RuleDescription: rule.Description,
				Severity:        rule.Severity,
				Message:         fmt.Sprintf("%s rule triggered. Value: %v, Expected: %s %v", rule.Name, value, rule.Operator, expectedValue),
				Value:           value,
				ExpectedValue:   expectedValue,
			}
			alerts = append(alerts, alert)
			log.Info().
				Str("cluster", clusterName).
				Str("rule", rule.Name).
				Str("severity", rule.Severity).
				Interface("value", value).
				Interface("expected", expectedValue).
				Msg("Rule triggered")
		}
	}

	return alerts
}

func (e *Evaluator) evaluateRule(rule config.Rule, resp *models.PatroniResponse) (bool, interface{}, interface{}, error) {
	if rule.Check != "" {
		switch rule.Check {
		case "sync_replica_count":
			return evaluateSyncReplicaCount(resp.Replication, rule.Operator, rule.Value)
		case "deep_replication_status":
			return evaluateDeepReplicationStatus(resp.Replication)
		default:
			return false, nil, nil, fmt.Errorf("unsupported check: %s", rule.Check)
		}
	}

	parts := strings.Split(rule.Path, ".")
	if len(parts) == 0 {
		return false, nil, nil, fmt.Errorf("invalid path: %s", rule.Path)
	}

	value, err := getValueFromPath(resp, parts)
	if err != nil {
		return false, nil, nil, err
	}

	return evaluateCondition(value, rule.Operator, rule.Value)
}

func evaluateSyncReplicaCount(replications []models.ReplicationInfo, operator string, expectedValue interface{}) (bool, interface{}, interface{}, error) {
	syncCount := 0
	for _, repl := range replications {
		if repl.SyncState == "sync" {
			syncCount++
		}
	}

	return evaluateCondition(syncCount, operator, expectedValue)
}

type DeepReplicationOptions struct {
	MaxReplayLagSeconds int              // Maximum allowed replication delay (seconds)
	CheckXlog           bool             // Check Xlog status
	TimeProvider        func() time.Time // Time provider for testability
	HTTPClient          *resty.Client    // HTTP client for testability
}

// defaultHTTPClient creates the default HTTP client
func defaultHTTPClient() *resty.Client {
	client := resty.New()
	client.SetTimeout(10 * time.Second)
	client.SetRetryCount(2)
	client.SetRetryWaitTime(1 * time.Second)
	client.SetRetryMaxWaitTime(3 * time.Second)
	return client
}

// timeNow, default function that returns the current time
func timeNow() time.Time {
	return time.Now()
}

// parseTimestamp parses the given timestamp format
func parseTimestamp(timestamp string) (time.Time, error) {
	return time.Parse("2006-01-02 15:04:05.999999-07:00", timestamp)
}

// calculateReplicationLag calculates the replication lag
func calculateReplicationLag(replayedTimestamp string, timeProvider func() time.Time) (float64, error) {
	replayedTime, err := parseTimestamp(replayedTimestamp)
	if err != nil {
		return 0, fmt.Errorf("could not parse replayed timestamp: %w", err)
	}

	now := timeProvider()
	return now.Sub(replayedTime).Seconds(), nil
}

// checkReplicationLag checks replication lag and returns information in case of excessive delay
func checkReplicationLag(
	replicaInfo string,
	replicaURL string,
	replayedTimestamp string,
	maxLagSeconds int,
	parentName string,
	depth int,
	timeProvider func() time.Time,
) (bool, string, error) {
	lagSeconds, err := calculateReplicationLag(replayedTimestamp, timeProvider)
	if err != nil {
		log.Error().Err(err).
			Str("replica", replicaInfo).
			Str("url", replicaURL).
			Str("replayed_timestamp", replayedTimestamp).
			Str("parent", parentName).
			Int("depth", depth).
			Msg("Could not parse replayed timestamp")
		return false, "", err
	}

	if lagSeconds > float64(maxLagSeconds) {
		log.Error().
			Str("replica", replicaInfo).
			Str("url", replicaURL).
			Str("replayed_timestamp", replayedTimestamp).
			Float64("lag_seconds", lagSeconds).
			Int("max_allowed_lag", maxLagSeconds).
			Str("parent", parentName).
			Int("depth", depth).
			Msg("Replica replication lag is too high")

		return false, fmt.Sprintf("%s (replay lag: %.1fs, parent: %s)",
			replicaInfo, lagSeconds, parentName), nil
	}

	log.Debug().
		Str("replica", replicaInfo).
		Str("url", replicaURL).
		Str("replayed_timestamp", replayedTimestamp).
		Float64("lag_seconds", lagSeconds).
		Str("parent", parentName).
		Int("depth", depth).
		Msg("Replica replication lag is at an acceptable level")

	return true, "", nil
}

func evaluateDeepReplicationStatus(replications []models.ReplicationInfo) (bool, interface{}, interface{}, error) {
	// Varsayılan değerler
	opts := DeepReplicationOptions{
		MaxReplayLagSeconds: 30,
		CheckXlog:           true,
		TimeProvider:        timeNow,
		HTTPClient:          defaultHTTPClient(),
	}

	return evaluateDeepReplicationStatusWithOptions(replications, opts)
}

func evaluateDeepReplicationStatusWithOptions(replications []models.ReplicationInfo, opts DeepReplicationOptions) (bool, interface{}, interface{}, error) {
	// If time provider is not specified, use the default time provider
	if opts.TimeProvider == nil {
		opts.TimeProvider = timeNow
	}

	// If HTTP client is not specified, use the default HTTP client
	if opts.HTTPClient == nil {
		opts.HTTPClient = defaultHTTPClient()
	}

	allRunning := true
	problemReplicas := []string{}

	visited := make(map[string]bool)

	var checkReplicas func(replications []models.ReplicationInfo, depth int, parentName string)

	checkReplicas = func(replications []models.ReplicationInfo, depth int, parentName string) {
		if depth > 5 {
			log.Warn().
				Str("parent", parentName).
				Msg("Maximum replication check depth reached (5)")
			return
		}

		for _, repl := range replications {
			if repl.ClientAddr == "" {
				log.Warn().
					Str("replica", repl.ApplicationName).
					Str("parent", parentName).
					Msg("Client_addr not found for replication, skipping")
				continue
			}

			replicaKey := fmt.Sprintf("%s:%s", repl.ClientAddr, repl.ApplicationName)
			if visited[replicaKey] {
				log.Debug().
					Str("replica", repl.ApplicationName).
					Str("client_addr", repl.ClientAddr).
					Msg("This replica was checked before, skipping")
				continue
			}

			visited[replicaKey] = true

			replicaURL := fmt.Sprintf("http://%s:8008", repl.ClientAddr)
			var replicaResp models.PatroniResponse

			resp, err := opts.HTTPClient.R().
				SetResult(&replicaResp).
				SetHeader("Accept", "application/json").
				SetError(&replicaResp).
				Get(replicaURL)

			if err != nil {
				log.Error().Err(err).
					Str("replica", repl.ApplicationName).
					Str("url", replicaURL).
					Str("parent", parentName).
					Int("depth", depth).
					Msg("Could not access replica")
				allRunning = false
				problemReplicas = append(problemReplicas, fmt.Sprintf("%s (parent: %s)", repl.ApplicationName, parentName))
				continue
			}

			if resp.IsError() {
				log.Warn().
					Str("replica", repl.ApplicationName).
					Str("url", replicaURL).
					Int("status", resp.StatusCode()).
					Str("parent", parentName).
					Int("depth", depth).
					Msg("Replica returned HTTP error code, but response content is being checked")

				respBody := string(resp.Body())

				if (replicaResp.State == "" || replicaResp.Role == "") && strings.Contains(respBody, "state") {
					var manualResp map[string]interface{}
					if err := json.Unmarshal([]byte(respBody), &manualResp); err == nil {
						if state, ok := manualResp["state"].(string); ok && state != "" {
							log.Info().
								Str("replica", repl.ApplicationName).
								Str("url", replicaURL).
								Str("manual_state", state).
								Str("parent", parentName).
								Int("depth", depth).
								Msg("Manually extracted state value")
							replicaResp.State = state
						}

						if role, ok := manualResp["role"].(string); ok && role != "" {
							log.Info().
								Str("replica", repl.ApplicationName).
								Str("url", replicaURL).
								Str("manual_role", role).
								Str("parent", parentName).
								Int("depth", depth).
								Msg("Manually extracted role value")
							replicaResp.Role = role
						}

						// Manually extract xlog information
						if xlogData, ok := manualResp["xlog"].(map[string]interface{}); ok {
							xlog := models.XLog{}

							if value, ok := xlogData["paused"].(bool); ok {
								xlog.Paused = value
							}

							if value, ok := xlogData["replayed_timestamp"].(string); ok {
								xlog.ReplayedTimestamp = value
							}

							if value, ok := xlogData["replayed_location"].(float64); ok {
								xlog.ReplayedLocation = int64(value)
							}

							if value, ok := xlogData["received_location"].(float64); ok {
								xlog.ReceivedLocation = int64(value)
							}

							replicaResp.XLog = xlog

							log.Info().
								Str("replica", repl.ApplicationName).
								Str("url", replicaURL).
								Bool("paused", xlog.Paused).
								Str("replayed_timestamp", xlog.ReplayedTimestamp).
								Str("parent", parentName).
								Int("depth", depth).
								Msg("Manually extracted xlog values")
						}
					}
				}

				if replicaResp.State == "" {
					log.Error().
						Str("replica", repl.ApplicationName).
						Str("url", replicaURL).
						Int("status", resp.StatusCode()).
						Str("body", string(resp.Body())).
						Str("parent", parentName).
						Int("depth", depth).
						Msg("Replica returned HTTP error code and does not contain valid status information")
					allRunning = false
					problemReplicas = append(problemReplicas, fmt.Sprintf("%s (parent: %s)", repl.ApplicationName, parentName))
					continue
				}
			}

			if replicaResp.State == "" {
				log.Error().
					Str("replica", repl.ApplicationName).
					Str("url", replicaURL).
					Str("body", string(resp.Body())).
					Str("parent", parentName).
					Int("depth", depth).
					Msg("Replica state information not found")
				allRunning = false
				problemReplicas = append(problemReplicas, fmt.Sprintf("%s (parent: %s)", repl.ApplicationName, parentName))
				continue
			}

			if replicaResp.State != "running" {
				log.Error().
					Str("replica", repl.ApplicationName).
					Str("url", replicaURL).
					Str("state", replicaResp.State).
					Str("parent", parentName).
					Int("depth", depth).
					Msg("Replica is not running")
				allRunning = false
				problemReplicas = append(problemReplicas,
					fmt.Sprintf("%s (state: %s, parent: %s)", repl.ApplicationName, replicaResp.State, parentName))
				continue
			}

			// XLog check - If active
			if opts.CheckXlog {
				// Paused check
				if replicaResp.XLog.Paused {
					log.Error().
						Str("replica", repl.ApplicationName).
						Str("url", replicaURL).
						Str("parent", parentName).
						Int("depth", depth).
						Msg("Replica xlog replication is paused")
					allRunning = false
					problemReplicas = append(problemReplicas,
						fmt.Sprintf("%s (xlog paused, parent: %s)", repl.ApplicationName, parentName))
					continue
				}

				// Replikasyon gecikmesi kontrolü
				if replicaResp.XLog.ReplayedTimestamp != "" {
					isOk, errorMessage, err := checkReplicationLag(
						repl.ApplicationName,
						replicaURL,
						replicaResp.XLog.ReplayedTimestamp,
						opts.MaxReplayLagSeconds,
						parentName,
						depth,
						opts.TimeProvider,
					)

					if err != nil {
						// Hata loglama zaten checkReplicationLag içinde yapılıyor
						continue
					}

					if !isOk {
						allRunning = false
						problemReplicas = append(problemReplicas, errorMessage)
						continue
					}
				}
			}

			log.Debug().
				Str("replica", repl.ApplicationName).
				Str("url", replicaURL).
				Str("state", replicaResp.State).
				Str("role", replicaResp.Role).
				Str("parent", parentName).
				Int("depth", depth).
				Msg("Replica status checked")

			if replicaResp.Role == "standby_leader" && len(replicaResp.Replication) > 0 {
				log.Info().
					Str("replica", repl.ApplicationName).
					Str("url", replicaURL).
					Int("sub_replica_count", len(replicaResp.Replication)).
					Str("parent", parentName).
					Int("depth", depth).
					Msg("Checking sub-replicas of standby leader replica")

				checkReplicas(replicaResp.Replication, depth+1, repl.ApplicationName)
			}
		}
	}

	checkReplicas(replications, 1, "master")

	if allRunning {
		return true, "all replicas running", "running", nil
	}

	return false,
		fmt.Sprintf("problematic replicas: %s", strings.Join(problemReplicas, ", ")),
		"all running",
		nil
}

func getValueFromPath(resp *models.PatroniResponse, parts []string) (interface{}, error) {
	var current interface{} = resp

	for _, part := range parts {
		v := reflect.ValueOf(current)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}

		if v.Kind() != reflect.Struct {
			return nil, fmt.Errorf("invalid path: %s is not a structure", part)
		}

		t := v.Type()
		fieldFound := false
		var f reflect.Value

		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			jsonTag := field.Tag.Get("json")
			jsonName := strings.Split(jsonTag, ",")[0]

			if jsonName == part || strings.EqualFold(field.Name, part) {
				f = v.Field(i)
				fieldFound = true
				break
			}
		}

		if !fieldFound {
			return nil, fmt.Errorf("field not found: %s", part)
		}

		current = f.Interface()
	}

	return current, nil
}

func evaluateCondition(actual interface{}, operator string, expected interface{}) (bool, interface{}, interface{}, error) {
	switch operator {
	case "eq", "==", "equals":
		return evaluateEquals(actual, expected)
	case "ne", "!=", "not_equals":
		triggered, a, e, err := evaluateEquals(actual, expected)
		return !triggered, a, e, err
	case "gt", ">", "greater_than":
		return evaluateGreaterThan(actual, expected)
	case "lt", "<", "less_than":
		return evaluateLessThan(actual, expected)
	case "ge", ">=", "greater_than_or_equals":
		return evaluateGreaterThanOrEquals(actual, expected)
	case "le", "<=", "less_than_or_equals":
		return evaluateLessThanOrEquals(actual, expected)
	case "contains":
		return evaluateContains(actual, expected)
	case "not_contains":
		triggered, a, e, err := evaluateContains(actual, expected)
		return !triggered, a, e, err
	case "time_diff_less_than":
		return evaluateTimeDiffLessThan(actual, expected)
	case "time_diff_greater_than":
		return evaluateTimeDiffGreaterThan(actual, expected)
	default:
		return false, actual, expected, fmt.Errorf("unsupported operator: %s", operator)
	}
}

func evaluateEquals(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if str, ok := actual.(string); ok {
		if expStr, ok := expected.(string); ok {
			return str == expStr, actual, expected, nil
		}
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected), actual, expected, nil
	}

	if isNumeric(actual) && isNumeric(expected) {
		a, err := toFloat64(actual)
		if err != nil {
			return false, actual, expected, err
		}
		e, err := toFloat64(expected)
		if err != nil {
			return false, actual, expected, err
		}
		return a == e, actual, expected, nil
	}

	if b1, ok := actual.(bool); ok {
		if b2, ok := expected.(bool); ok {
			return b1 == b2, actual, expected, nil
		}
		if str, ok := expected.(string); ok {
			b2, err := strconv.ParseBool(str)
			if err != nil {
				return false, actual, expected, err
			}
			return b1 == b2, actual, expected, nil
		}
	}

	return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected), actual, expected, nil
}

func evaluateGreaterThan(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if !isNumeric(actual) || !isNumeric(expected) {
		return false, actual, expected, fmt.Errorf("not numeric values: %v, %v", actual, expected)
	}

	a, err := toFloat64(actual)
	if err != nil {
		return false, actual, expected, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, actual, expected, err
	}

	return a > e, actual, expected, nil
}

func evaluateLessThan(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if !isNumeric(actual) || !isNumeric(expected) {
		return false, actual, expected, fmt.Errorf("not numeric values: %v, %v", actual, expected)
	}

	a, err := toFloat64(actual)
	if err != nil {
		return false, actual, expected, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, actual, expected, err
	}

	return a < e, actual, expected, nil
}

func evaluateGreaterThanOrEquals(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if !isNumeric(actual) || !isNumeric(expected) {
		return false, actual, expected, fmt.Errorf("not numeric values: %v, %v", actual, expected)
	}

	a, err := toFloat64(actual)
	if err != nil {
		return false, actual, expected, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, actual, expected, err
	}

	return a >= e, actual, expected, nil
}

func evaluateLessThanOrEquals(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if !isNumeric(actual) || !isNumeric(expected) {
		return false, actual, expected, fmt.Errorf("not numeric values: %v, %v", actual, expected)
	}

	a, err := toFloat64(actual)
	if err != nil {
		return false, actual, expected, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, actual, expected, err
	}

	return a <= e, actual, expected, nil
}

func evaluateContains(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if str, ok := actual.(string); ok {
		return strings.Contains(str, fmt.Sprintf("%v", expected)), actual, expected, nil
	}
	return false, actual, expected, fmt.Errorf("not a text value: %v", actual)
}

func evaluateTimeDiffLessThan(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if timestamp, ok := actual.(int64); ok {
		now := time.Now().Unix()
		diff := now - timestamp

		expectedSec, err := toFloat64(expected)
		if err != nil {
			return false, actual, expected, err
		}

		return diff < int64(expectedSec), diff, expectedSec, nil
	}

	if timeStr, ok := actual.(string); ok {
		t, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return false, actual, expected, fmt.Errorf("invalid time format: %v", actual)
		}

		now := time.Now()
		diff := now.Sub(t).Seconds()

		expectedSec, err := toFloat64(expected)
		if err != nil {
			return false, actual, expected, err
		}

		return diff < expectedSec, diff, expectedSec, nil
	}

	return false, actual, expected, fmt.Errorf("not a time value: %v", actual)
}

func evaluateTimeDiffGreaterThan(actual interface{}, expected interface{}) (bool, interface{}, interface{}, error) {
	if timestamp, ok := actual.(int64); ok {
		now := time.Now().Unix()
		diff := now - timestamp

		expectedSec, err := toFloat64(expected)
		if err != nil {
			return false, actual, expected, err
		}

		return diff > int64(expectedSec), diff, expectedSec, nil
	}

	if timeStr, ok := actual.(string); ok {
		t, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return false, actual, expected, fmt.Errorf("invalid time format: %v", actual)
		}

		now := time.Now()
		diff := now.Sub(t).Seconds()

		expectedSec, err := toFloat64(expected)
		if err != nil {
			return false, actual, expected, err
		}

		return diff > expectedSec, diff, expectedSec, nil
	}

	return false, actual, expected, fmt.Errorf("not a time value: %v", actual)
}

func isNumeric(v interface{}) bool {
	switch val := v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	case string:
		_, err := strconv.ParseFloat(val, 64)
		return err == nil
	}
	return false
}

func toFloat64(v interface{}) (float64, error) {
	switch i := v.(type) {
	case int:
		return float64(i), nil
	case int8:
		return float64(i), nil
	case int16:
		return float64(i), nil
	case int32:
		return float64(i), nil
	case int64:
		return float64(i), nil
	case uint:
		return float64(i), nil
	case uint8:
		return float64(i), nil
	case uint16:
		return float64(i), nil
	case uint32:
		return float64(i), nil
	case uint64:
		return float64(i), nil
	case float32:
		return float64(i), nil
	case float64:
		return i, nil
	case string:
		return strconv.ParseFloat(i, 64)
	}
	return 0, fmt.Errorf("cannot convert to float64: %v (%T)", v, v)
}
