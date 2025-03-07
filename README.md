# Patroni Alert System

This application is a Go application that monitors PostgreSQL Patroni clusters and generates alarms based on specified rules.

## Features

- Supports multiple Patroni clusters
- Customizable monitoring rules
- Multiple alarm mechanisms (Slack, Email, Webhook, Telegram)
- Flexible configuration
- Periodic checks
- Deep replication checks

## Requirements

- Go 1.22.2 or higher

## Installation

```bash
# Clone the project
git clone https://github.com/Trendyol/patroni-watcher.git
cd patroni-watcher

# Install dependencies
go mod download

# Build the application
go build -o patroni-watcher ./cmd/patroni-watcher
```

## Configuration

By default, the application uses the `./config/config.yaml` file. You can use the `-config` parameter to specify a different configuration file.

Also you can see example configration on `./config/config_example.yaml`
```yaml
# Example configuration
log_level: "info"
check_interval: 60s

clusters:
  - name: "pg-cluster-01"
    endpoint: "http://10.97.22.141:8008/"
    username: ""
    password: ""

rules:
  - name: "master_check"
    description: "Cluster should be in master role"
    path: "role"
    operator: "equals"
    value: "master"
    severity: "critical"

alerts:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    channel: "#database-alerts"
```

### Configuration Fields

#### Main Configuration

| Field | Description | Default |
|------|----------|------------|
| log_level | Log level (debug, info, warn, error, fatal) | "info" |
| check_interval | Check interval (e.g., 60s, 5m, 1h) | 1m |
| clusters | List of clusters to monitor | [] |
| rules | List of rules to apply | [] |
| alerts | Configuration of alert mechanisms | {} |

#### Cluster Configuration

| Field | Description |
|------|----------|
| name | Cluster name |
| endpoint | Patroni API address (http://host:port/) |
| username | Username for authentication (optional) |
| password | Password for authentication (optional) |

#### Rule Configuration

| Field | Description |
|------|----------|
| name | Rule name |
| description | Rule description |
| path | JSON path of the value to check (e.g., "role", "state", "dcs_last_seen") |
| operator | Operator (equals, not_equals, greater_than, less_than, contains, time_diff_less_than, etc.) |
| value | Expected value |
| severity | Alert severity (critical, high, medium, low) |

#### Operators

| Operator | Description | Example |
|----------|----------|-------|
| equals, eq, == | Equality | "role" == "master" |
| not_equals, ne, != | Not equals | "state" != "stopped" |
| greater_than, gt, > | Greater than | "timeline" > 10 |
| less_than, lt, < | Less than | "timeline" < 100 |
| greater_than_or_equals, ge, >= | Greater than or equals | "replication_count" >= 1 |
| less_than_or_equals, le, <= | Less than or equals | "lag" <= 1000 |
| contains | Contains | "scope" contains "prod" |
| not_contains | Does not contain | "scope" not_contains "test" |
| time_diff_less_than | Time difference less than (seconds) | "dcs_last_seen" time_diff_less_than 180 |
| time_diff_greater_than | Time difference greater than (seconds) | "postmaster_start_time" time_diff_greater_than 86400 |

## Deep Cluster Replication Check

The deep cluster replication check is an advanced feature that enables comprehensive monitoring of PostgreSQL replication across multiple layers of replica servers in a cascade replication setup. This feature recursively traverses the entire replication tree, checking the health and status of each replica in the chain.

### How Deep Replication Check Works

1. **Multi-level Traversal**: The system starts by checking replicas directly connected to the master, then follows the replication chain to standby leaders and their replicas, up to a maximum depth of 5 levels.

2. **Health Checks per Replica**:
   - Verifies that each replica is accessible via its API
   - Confirms the replica is in "running" state
   - Checks if replication is active (not paused)
   - Measures replication lag and compares it against threshold

3. **Replication Lag Monitoring**: For each replica, the system:
   - Reads the `replayed_timestamp` from the replica's status
   - Calculates the difference between current time and the last replayed transaction
   - Generates alerts if lag exceeds the configured threshold (default: 30 seconds)

4. **Cycle Detection**: The system maintains a record of visited replicas to avoid endless loops in case of circular replication setups.

### Example Configuration

To enable deep replication checks, add a rule like this to your configuration:

```yaml
rules:
  - name: "deep_replication_check"
    description: "Verify all replicas in the replication chain are running with acceptable lag"
    path: "deep_replication_status"
    operator: "equals"
    value: true
    severity: "critical"
```

### Advanced Options

The deep replication check can be customized with the following options:

- **MaxReplayLagSeconds**: Maximum allowed replication delay in seconds (default: 30)
- **CheckXlog**: Whether to check the replication status using xlog information (default: true)

This feature provides a comprehensive monitoring solution for complex PostgreSQL replication setups, ensuring that replication problems are detected early, even in cascaded configurations.

## Usage

```bash
# Run with default configuration
./patroni-watcher

# Run with custom configuration file
./patroni-watcher -config /path/to/config.yaml
```

## Running with Docker

```bash
# Build Docker image
docker build -t patroni-watcher .

# Run Docker container
docker run -v $(pwd)/config:/app/config patroni-watcher
```

## Example Patroni API Response

```json
{
  "state": "running",
  "postmaster_start_time": "2025-02-20 13:22:01.804189+03:00",
  "role": "master",
  "server_version": 140012,
  "xlog": {
    "location": 59922741796784
  },
  "timeline": 33,
  "replication": [
    {
      "usename": "repl_user",
      "application_name": "pgs-p-discovery-payment-01-data-3",
      "client_addr": "10.97.21.175",
      "state": "streaming",
      "sync_state": "async",
      "sync_priority": 0
    },
    {
      "usename": "repl_user",
      "application_name": "pgs-p-discovery-payment-01-data-1",
      "client_addr": "10.97.20.193",
      "state": "streaming",
      "sync_state": "sync",
      "sync_priority": 1
    }
  ],
  "dcs_last_seen": 1741067815,
  "patroni": {
    "version": "3.3.0",
    "scope": "pg-discovery-payment-01",
    "name": "pgs-p-discovery-payment-01-data-2"
  }
}
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for more information. 