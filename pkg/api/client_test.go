package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/trendyol/patroni-watcher/pkg/config"
)

// TestNewClient tests the creation of a new client
func TestNewClient(t *testing.T) {
	client := NewClient()
	assert.NotNil(t, client)
	assert.NotNil(t, client.httpClient)
}

// TestGetClusterStatusSimple is a simplified test that focuses on basic functionality
func TestGetClusterStatusSimple(t *testing.T) {
	// Create a new client with a mock HTTP client
	client := &Client{
		httpClient: resty.New(),
	}

	// Enable HTTP mocking
	httpmock.ActivateNonDefault(client.httpClient.GetClient())
	defer httpmock.DeactivateAndReset()

	// Define test cluster
	cluster := config.Cluster{
		Name:     "test-cluster",
		Endpoint: "http://patroni.example.com:8008",
	}

	// Create a simplified patroni response
	mockResponseJSON := `{
		"state": "running",
		"role": "master",
		"patroni": {
			"version": "3.0.0",
			"name": "node1"
		}
	}`

	// Register mock responder
	httpmock.RegisterResponder("GET", cluster.Endpoint,
		httpmock.NewStringResponder(200, mockResponseJSON))

	// Call the method under test
	response, err := client.GetClusterStatus(cluster)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "running", response.State)
	assert.Equal(t, "master", response.Role)
	assert.Equal(t, "node1", response.Patroni.Name)
}

// TestGetClusterStatusWithError tests error handling
func TestGetClusterStatusWithError(t *testing.T) {
	// Create a new client with a mock HTTP client
	client := &Client{
		httpClient: resty.New(),
	}

	// Enable HTTP mocking
	httpmock.ActivateNonDefault(client.httpClient.GetClient())
	defer httpmock.DeactivateAndReset()

	// Define test cluster
	cluster := config.Cluster{
		Name:     "error-cluster",
		Endpoint: "http://patroni.example.com:8008",
	}

	// Register 500 error response
	httpmock.RegisterResponder("GET", cluster.Endpoint,
		httpmock.NewStringResponder(500, "Internal Server Error"))

	// Call the method under test
	response, err := client.GetClusterStatus(cluster)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "http error")
}

// TestGetClusterStatusWithNetworkError tests network error handling
func TestGetClusterStatusWithNetworkError(t *testing.T) {
	// Create a new client with a mock HTTP client
	client := &Client{
		httpClient: resty.New(),
	}

	// Enable HTTP mocking
	httpmock.ActivateNonDefault(client.httpClient.GetClient())
	defer httpmock.DeactivateAndReset()

	// Define test cluster
	cluster := config.Cluster{
		Name:     "network-error",
		Endpoint: "http://non-existent-host:8008",
	}

	// Register network error
	httpmock.RegisterResponder("GET", cluster.Endpoint,
		func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network error")
		})

	// Call the method under test
	response, err := client.GetClusterStatus(cluster)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "request error")
}

// TestGetClusterStatusWithAuth tests authentication
func TestGetClusterStatusWithAuth(t *testing.T) {
	// Create a new client with a mock HTTP client
	client := &Client{
		httpClient: resty.New(),
	}

	// Enable HTTP mocking
	httpmock.ActivateNonDefault(client.httpClient.GetClient())
	defer httpmock.DeactivateAndReset()

	// Define test cluster with auth
	cluster := config.Cluster{
		Name:     "auth-cluster",
		Endpoint: "http://patroni.example.com:8008",
		Username: "testuser",
		Password: "testpass",
	}

	// Register mock responder that checks auth
	httpmock.RegisterResponder("GET", cluster.Endpoint,
		func(req *http.Request) (*http.Response, error) {
			// Verify Basic Auth is set correctly
			username, password, ok := req.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, cluster.Username, username)
			assert.Equal(t, cluster.Password, password)

			// Return successful JSON response
			mockResponseJSON := `{
				"state": "running",
				"role": "replica",
				"patroni": {
					"version": "3.0.0",
					"name": "node2"
				}
			}`
			return httpmock.NewStringResponse(200, mockResponseJSON), nil
		})

	// Call the method under test
	response, err := client.GetClusterStatus(cluster)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "running", response.State)
	assert.Equal(t, "replica", response.Role)
	assert.Equal(t, "node2", response.Patroni.Name)

	// Verify the number of calls made
	info := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, info["GET "+cluster.Endpoint])
}
