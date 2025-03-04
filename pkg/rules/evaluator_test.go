package rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
	"github.com/trendyol/patroni-watcher/pkg/config"
	"github.com/trendyol/patroni-watcher/pkg/models"
)

func mockTimeNow() time.Time {
	return time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
}

func TestIsNumeric(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected bool
	}{
		{"Integer", 10, true},
		{"Float", 10.5, true},
		{"String number", "10", true},
		{"String float", "10.5", true},
		{"String text", "hello", false},
		{"Boolean", true, false},
		{"Nil", nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isNumeric(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestToFloat64(t *testing.T) {
	testCases := []struct {
		name          string
		input         interface{}
		expected      float64
		expectError   bool
		errorContains string
	}{
		{"Integer", 10, 10.0, false, ""},
		{"Int8", int8(8), 8.0, false, ""},
		{"Int16", int16(16), 16.0, false, ""},
		{"Int32", int32(32), 32.0, false, ""},
		{"Int64", int64(64), 64.0, false, ""},
		{"Uint", uint(10), 10.0, false, ""},
		{"Uint8", uint8(8), 8.0, false, ""},
		{"Uint16", uint16(16), 16.0, false, ""},
		{"Uint32", uint32(32), 32.0, false, ""},
		{"Uint64", uint64(64), 64.0, false, ""},
		{"Float32", float32(32.5), 32.5, false, ""},
		{"Float64", 64.5, 64.5, false, ""},
		{"String integer", "10", 10.0, false, ""},
		{"String float", "10.5", 10.5, false, ""},
		{"Invalid string", "hello", 0, true, "invalid syntax"},
		{"Boolean", true, 0, true, "cannot convert to float64"},
		{"Nil", nil, 0, true, "cannot convert to float64"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := toFloat64(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestEvaluateEquals(t *testing.T) {
	testCases := []struct {
		name     string
		actual   interface{}
		expected interface{}
		result   bool
		hasError bool
	}{
		{"String equals", "test", "test", true, false},
		{"String not equals", "test", "other", false, false},
		{"Number equals", 10, 10, true, false},
		{"Number not equals", 10, 20, false, false},
		{"Mixed number string equals", 10, "10", true, false},
		{"Mixed number string not equals", 10, "20", false, false},
		{"Boolean equals", true, true, true, false},
		{"Boolean not equals", true, false, false, false},
		{"Boolean and string", true, "true", true, false},
		{"Invalid boolean string", true, "invalid", false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, actual, expected, err := evaluateEquals(tc.actual, tc.expected)

			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.result, result)
				assert.Equal(t, tc.actual, actual)
				assert.Equal(t, tc.expected, expected)
			}
		})
	}
}

func TestEvaluateGreaterThan(t *testing.T) {
	testCases := []struct {
		name     string
		actual   interface{}
		expected interface{}
		result   bool
		hasError bool
	}{
		{"Number greater", 20, 10, true, false},
		{"Number equal", 10, 10, false, false},
		{"Number less", 5, 10, false, false},
		{"String number greater", "20", 10, true, false},
		{"String comparison", "text", "other", true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, actual, expected, err := evaluateGreaterThan(tc.actual, tc.expected)

			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.result, result)
				assert.Equal(t, tc.actual, actual)
				assert.Equal(t, tc.expected, expected)
			}
		})
	}
}

func TestEvaluateLessThan(t *testing.T) {
	testCases := []struct {
		name     string
		actual   interface{}
		expected interface{}
		result   bool
		hasError bool
	}{
		{"Number less", 5, 10, true, false},
		{"Number equal", 10, 10, false, false},
		{"Number greater", 20, 10, false, false},
		{"String number less", "5", 10, true, false},
		{"String comparison", "text", "other", true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, actual, expected, err := evaluateLessThan(tc.actual, tc.expected)

			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.result, result)
				assert.Equal(t, tc.actual, actual)
				assert.Equal(t, tc.expected, expected)
			}
		})
	}
}

func TestEvaluateContains(t *testing.T) {
	testCases := []struct {
		name     string
		actual   interface{}
		expected interface{}
		result   bool
		hasError bool
	}{
		{"String contains", "this is a test", "test", true, false},
		{"String not contains", "this is a test", "example", false, false},
		{"Number as expected", "this is 123", 123, true, false},
		{"Non-string actual", 123, "test", false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, actual, expected, err := evaluateContains(tc.actual, tc.expected)

			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.result, result)
				assert.Equal(t, tc.actual, actual)
				assert.Equal(t, tc.expected, expected)
			}
		})
	}
}

func TestCalculateReplicationLag(t *testing.T) {
	mockTime := mockTimeNow

	testCases := []struct {
		name              string
		replayedTimestamp string
		expectedLag       float64
		expectError       bool
	}{
		{
			name:              "10 seconds ago",
			replayedTimestamp: "2022-12-31 23:59:50.000000+00:00",
			expectedLag:       10.0,
			expectError:       false,
		},
		{
			name:              "1 minute ago",
			replayedTimestamp: "2022-12-31 23:59:00.000000+00:00",
			expectedLag:       60.0,
			expectError:       false,
		},
		{
			name:              "Future timestamp",
			replayedTimestamp: "2023-01-01 00:00:10.000000+00:00",
			expectedLag:       -10.0,
			expectError:       false,
		},
		{
			name:              "Invalid format",
			replayedTimestamp: "invalid",
			expectedLag:       0,
			expectError:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lag, err := calculateReplicationLag(tc.replayedTimestamp, mockTime)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedLag, lag)
			}
		})
	}
}

func TestEvaluateSyncReplicaCount(t *testing.T) {
	testCases := []struct {
		name          string
		replications  []models.ReplicationInfo
		operator      string
		expectedValue interface{}
		result        bool
		expectedCount int
		expectError   bool
		errorContains string
	}{
		{
			name: "Two sync replicas equal",
			replications: []models.ReplicationInfo{
				{SyncState: "sync"},
				{SyncState: "sync"},
				{SyncState: "async"},
			},
			operator:      "==",
			expectedValue: 2,
			result:        true,
			expectedCount: 2,
			expectError:   false,
		},
		{
			name: "No sync replicas less than",
			replications: []models.ReplicationInfo{
				{SyncState: "async"},
				{SyncState: "async"},
			},
			operator:      "<",
			expectedValue: 1,
			result:        true,
			expectedCount: 0,
			expectError:   false,
		},
		{
			name: "One sync replica greater than",
			replications: []models.ReplicationInfo{
				{SyncState: "sync"},
				{SyncState: "async"},
			},
			operator:      ">",
			expectedValue: 0,
			result:        true,
			expectedCount: 1,
			expectError:   false,
		},
		{
			name: "Invalid operator",
			replications: []models.ReplicationInfo{
				{SyncState: "sync"},
			},
			operator:      "invalid",
			expectedValue: 1,
			result:        false,
			expectedCount: 1,
			expectError:   true,
			errorContains: "unsupported operator",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, actual, expected, err := evaluateSyncReplicaCount(tc.replications, tc.operator, tc.expectedValue)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.result, result)
				assert.Equal(t, tc.expectedCount, actual)
				assert.Equal(t, tc.expectedValue, expected)
			}
		})
	}
}

func TestEvaluator_EvaluateRules(t *testing.T) {
	rules := []config.Rule{
		{
			Name:        "test_rule_state",
			Description: "State should be running",
			Path:        "state",
			Operator:    "==",
			Value:       "running",
			Severity:    "critical",
		},
		{
			Name:        "test_rule_sync_replica",
			Description: "At least one sync replica",
			Check:       "sync_replica_count",
			Operator:    ">=",
			Value:       1,
			Severity:    "warning",
		},
	}

	response := &models.PatroniResponse{
		State: "running",
		Replication: []models.ReplicationInfo{
			{ApplicationName: "replica1", SyncState: "sync"},
			{ApplicationName: "replica2", SyncState: "async"},
		},
	}

	testCases := []struct {
		name               string
		state              string
		syncReplicas       int
		expectedAlertCount int
	}{
		{
			name:               "No alerts, all conditions met",
			state:              "running",
			syncReplicas:       1,
			expectedAlertCount: 0,
		},
		{
			name:               "State alert only",
			state:              "stopped",
			syncReplicas:       1,
			expectedAlertCount: 1,
		},
		{
			name:               "Replica alert only",
			state:              "running",
			syncReplicas:       0,
			expectedAlertCount: 1,
		},
		{
			name:               "Both alerts triggered",
			state:              "stopped",
			syncReplicas:       0,
			expectedAlertCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testResp := *response
			testResp.State = tc.state

			testReplication := make([]models.ReplicationInfo, 0)
			for i := 0; i < tc.syncReplicas; i++ {
				testReplication = append(testReplication, models.ReplicationInfo{
					ApplicationName: "replica" + fmt.Sprint(i),
					SyncState:       "sync",
				})
			}
			for i := 0; i < 2-tc.syncReplicas; i++ {
				testReplication = append(testReplication, models.ReplicationInfo{
					ApplicationName: "async" + fmt.Sprint(i),
					SyncState:       "async",
				})
			}
			testResp.Replication = testReplication

			evaluator := NewEvaluator(rules)
			alerts := evaluator.EvaluateRules("test-cluster", "http://test", &testResp)

			assert.Equal(t, tc.expectedAlertCount, len(alerts))
		})
	}
}

func TestCheckReplicationLag(t *testing.T) {
	mockTime := mockTimeNow

	testCases := []struct {
		name              string
		replayedTimestamp string
		maxLagSeconds     int
		expectedResult    bool
		expectedError     bool
	}{
		{
			name:              "Acceptable lag",
			replayedTimestamp: "2022-12-31 23:59:40.000000+00:00",
			maxLagSeconds:     30,
			expectedResult:    true,
			expectedError:     false,
		},
		{
			name:              "Excessive lag",
			replayedTimestamp: "2022-12-31 23:58:00.000000+00:00",
			maxLagSeconds:     30,
			expectedResult:    false,
			expectedError:     false,
		},
		{
			name:              "Invalid timestamp",
			replayedTimestamp: "invalid",
			maxLagSeconds:     30,
			expectedResult:    false,
			expectedError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, message, err := checkReplicationLag(
				"test-replica",
				"http://test:8008",
				tc.replayedTimestamp,
				tc.maxLagSeconds,
				"master",
				1,
				mockTime,
			)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
				if !tc.expectedResult {
					assert.NotEmpty(t, message)
				}
			}
		})
	}
}

func TestEvaluateDeepReplicationStatusWithOptions(t *testing.T) {
	mockTime := mockTimeNow

	createPatroniResponse := func(state, role string, paused bool, replayedTimestamp string) []byte {
		resp := map[string]interface{}{
			"state": state,
			"role":  role,
			"xlog": map[string]interface{}{
				"paused":             paused,
				"replayed_timestamp": replayedTimestamp,
				"replayed_location":  12345,
				"received_location":  67890,
			},
			"replication": []interface{}{},
		}

		bytes, _ := json.Marshal(resp)
		return bytes
	}

	testCases := []struct {
		name             string
		replicationInfos []models.ReplicationInfo
		replicaHandlers  map[string]http.HandlerFunc
		options          DeepReplicationOptions
		expectedResult   bool
		expectError      bool
	}{
		{
			name: "All replicas running and healthy",
			replicationInfos: []models.ReplicationInfo{
				{
					ApplicationName: "replica1",
					ClientAddr:      "replica1",
					SyncState:       "sync",
				},
				{
					ApplicationName: "replica2",
					ClientAddr:      "replica2",
					SyncState:       "async",
				},
			},
			replicaHandlers: map[string]http.HandlerFunc{
				"replica1": func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write(createPatroniResponse("running", "replica", false, "2022-12-31 23:59:40.000000+00:00"))
				},
				"replica2": func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write(createPatroniResponse("running", "replica", false, "2022-12-31 23:59:45.000000+00:00"))
				},
			},
			options: DeepReplicationOptions{
				MaxReplayLagSeconds: 30,
				CheckXlog:           true,
				TimeProvider:        mockTime,
			},
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "One replica with excessive lag",
			replicationInfos: []models.ReplicationInfo{
				{
					ApplicationName: "replica1",
					ClientAddr:      "replica1",
					SyncState:       "sync",
				},
				{
					ApplicationName: "lagging-replica",
					ClientAddr:      "lagging-replica",
					SyncState:       "async",
				},
			},
			replicaHandlers: map[string]http.HandlerFunc{
				"replica1": func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write(createPatroniResponse("running", "replica", false, "2022-12-31 23:59:40.000000+00:00"))
				},
				"lagging-replica": func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write(createPatroniResponse("running", "replica", false, "2022-12-31 23:55:00.000000+00:00"))
				},
			},
			options: DeepReplicationOptions{
				MaxReplayLagSeconds: 30,
				CheckXlog:           true,
				TimeProvider:        mockTime,
			},
			expectedResult: true,
			expectError:    false,
		},
		{
			name: "One replica in stopped state",
			replicationInfos: []models.ReplicationInfo{
				{
					ApplicationName: "stopped-replica",
					ClientAddr:      "stopped-replica",
					SyncState:       "sync",
				},
			},
			replicaHandlers: map[string]http.HandlerFunc{
				"stopped-replica": func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write(createPatroniResponse("stopped", "replica", false, "2022-12-31 23:59:40.000000+00:00"))
				},
			},
			options: DeepReplicationOptions{
				MaxReplayLagSeconds: 30,
				CheckXlog:           true,
				TimeProvider:        mockTime,
			},
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "One replica with paused xlog",
			replicationInfos: []models.ReplicationInfo{
				{
					ApplicationName: "paused-replica",
					ClientAddr:      "paused-replica",
					SyncState:       "sync",
				},
			},
			replicaHandlers: map[string]http.HandlerFunc{
				"paused-replica": func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write(createPatroniResponse("running", "replica", true, "2022-12-31 23:59:40.000000+00:00"))
				},
			},
			options: DeepReplicationOptions{
				MaxReplayLagSeconds: 30,
				CheckXlog:           true,
				TimeProvider:        mockTime,
			},
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "HTTP error accessing replica",
			replicationInfos: []models.ReplicationInfo{
				{
					ApplicationName: "error-replica",
					ClientAddr:      "error-replica",
					SyncState:       "sync",
				},
			},
			replicaHandlers: map[string]http.HandlerFunc{
				"error-replica": func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Internal server error"))
				},
			},
			options: DeepReplicationOptions{
				MaxReplayLagSeconds: 30,
				CheckXlog:           true,
				TimeProvider:        mockTime,
			},
			expectedResult: false,
			expectError:    false,
		},
		{
			name: "CheckXlog disabled",
			replicationInfos: []models.ReplicationInfo{
				{
					ApplicationName: "paused-replica",
					ClientAddr:      "paused-replica",
					SyncState:       "sync",
				},
			},
			replicaHandlers: map[string]http.HandlerFunc{
				"paused-replica": func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write(createPatroniResponse("running", "replica", true, "2022-12-31 23:55:00.000000+00:00"))
				},
			},
			options: DeepReplicationOptions{
				MaxReplayLagSeconds: 30,
				CheckXlog:           false,
				TimeProvider:        mockTime,
			},
			expectedResult: true,
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			servers := make(map[string]*httptest.Server)
			for host, handler := range tc.replicaHandlers {
				servers[host] = httptest.NewServer(handler)
				defer servers[host].Close()
			}

			replications := []models.ReplicationInfo{}
			for _, repl := range tc.replicationInfos {
				newRepl := repl
				if server, ok := servers[repl.ClientAddr]; ok {
					u := server.URL
					hostPort := u[7:]
					hostParts := strings.Split(hostPort, ":")

					if len(hostParts) > 0 {
						newRepl.ClientAddr = hostParts[0]
					}
				}
				replications = append(replications, newRepl)
			}

			transport := &testTransport{
				servers: servers,
			}

			client := resty.New()
			client.SetTimeout(1 * time.Second)
			client.SetTransport(transport)

			options := tc.options
			options.HTTPClient = client

			result, _, _, err := evaluateDeepReplicationStatusWithOptions(replications, options)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

type testTransport struct {
	servers map[string]*httptest.Server
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host

	hostParts := strings.Split(host, ":")
	if len(hostParts) >= 1 {
		baseHost := hostParts[0]

		for _, server := range t.servers {
			serverURL := server.URL
			if strings.Contains(serverURL, baseHost) {
				newReq := *req
				newReq.URL.Scheme = "http"
				newReq.URL.Host = serverURL[7:]

				return http.DefaultTransport.RoundTrip(&newReq)
			}
		}
	}

	return http.DefaultTransport.RoundTrip(req)
}
