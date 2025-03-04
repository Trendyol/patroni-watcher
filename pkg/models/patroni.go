package models

import (
	"time"
)

type PatroniResponse struct {
	State                string                 `json:"state"`
	PostmasterStartTime  string                 `json:"postmaster_start_time"`
	Role                 string                 `json:"role"`
	ServerVersion        int                    `json:"server_version"`
	XLog                 XLog                   `json:"xlog"`
	Timeline             int                    `json:"timeline"`
	Replication          []ReplicationInfo      `json:"replication"`
	DCSLastSeen          int64                  `json:"dcs_last_seen"`
	DBSID                string                 `json:"database_system_identifier"`
	PendingRestart       bool                   `json:"pending_restart"`
	PendingRestartReason map[string]interface{} `json:"pending_restart_reason"`
	Patroni              PatroniInfo            `json:"patroni"`
	ReplicationState     string                 `json:"replication_state"`
}

type XLog struct {
	Location          int64  `json:"location"`
	ReceivedLocation  int64  `json:"received_location"`
	ReplayedLocation  int64  `json:"replayed_location"`
	ReplayedTimestamp string `json:"replayed_timestamp"`
	Paused            bool   `json:"paused"`
}

type ReplicationInfo struct {
	Username        string `json:"usename"`
	ApplicationName string `json:"application_name"`
	ClientAddr      string `json:"client_addr"`
	State           string `json:"state"`
	SyncState       string `json:"sync_state"`
	SyncPriority    int    `json:"sync_priority"`
}

type PatroniInfo struct {
	Version string `json:"version"`
	Scope   string `json:"scope"`
	Name    string `json:"name"`
}

type NodeHealth struct {
	Role        string            `json:"role"`
	State       string            `json:"state"`
	Endpoint    string            `json:"endpoint"`
	IsHealthy   bool              `json:"is_healthy"`
	Name        string            `json:"name"`
	ErrorDetail string            `json:"error_detail,omitempty"`
	Replication []ReplicationInfo `json:"replication,omitempty"`
}

type ReplicationHealthResult struct {
	ClusterName   string       `json:"cluster_name"`
	MainNode      NodeHealth   `json:"main_node"`
	ReplicaNodes  []NodeHealth `json:"replica_nodes"`
	StandbyLeader NodeHealth   `json:"standby_leader"`
	Timestamp     time.Time    `json:"timestamp"`
}

type AlertEvent struct {
	ClusterName     string      `json:"cluster_name"`
	ClusterURL      string      `json:"cluster_url"`
	Timestamp       time.Time   `json:"timestamp"`
	RuleName        string      `json:"rule_name"`
	RuleDescription string      `json:"rule_description"`
	Severity        string      `json:"severity"`
	Message         string      `json:"message"`
	Value           interface{} `json:"value"`
	ExpectedValue   interface{} `json:"expected_value"`
}
