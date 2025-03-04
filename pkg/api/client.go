package api

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/trendyol/patroni-watcher/pkg/config"
	"github.com/trendyol/patroni-watcher/pkg/models"
)

type Client struct {
	httpClient *resty.Client
}

func NewClient() *Client {
	client := resty.New()
	client.SetTimeout(10 * time.Second)
	client.SetRetryCount(3)
	client.SetRetryWaitTime(1 * time.Second)
	client.SetRetryMaxWaitTime(5 * time.Second)

	return &Client{
		httpClient: client,
	}
}

func (c *Client) GetClusterStatus(cluster config.Cluster) (*models.PatroniResponse, error) {
	req := c.httpClient.R()

	if cluster.Username != "" && cluster.Password != "" {
		req = req.SetBasicAuth(cluster.Username, cluster.Password)
	}

	resp, err := req.Get(cluster.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("http error: %s, status code: %d", resp.Status(), resp.StatusCode())
	}

	log.Debug().
		Str("cluster", cluster.Name).
		Str("endpoint", cluster.Endpoint).
		Int("status", resp.StatusCode()).
		Msg("Patroni status retrieved")

	// Parse the JSON response manually
	var response models.PatroniResponse
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &response, nil
}
