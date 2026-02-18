# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains Python scripts for analyzing Solace broker event log files:

1. **analyze_client_connections.py** - Tracks connection metrics per source IP address
2. **analyze_client_reconnects.py** - Analyzes client reconnection patterns across log rotations

## Running the Analyzers

### Client Connection Analyzer (by IP)

Analyzes a single log file for connection metrics per source IP:

```bash
python3 analyze_client_connections.py <logfile>
# or
./analyze_client_connections.py <logfile>
```

### Client Reconnection Analyzer (by client name)

Analyzes a directory of rotated logs for client reconnection patterns:

```bash
python3 analyze_client_reconnects.py <log_directory>
# or
./analyze_client_reconnects.py <log_directory>
```

All scripts are executable and use `#!/usr/bin/env python3`.

### Log File Rotation

Event logs are rotated based on maximum size:
- Current log: `event.log` (newest)
- Rotated logs: `event.log.1`, `event.log.2`, ..., `event.log.N`
- **Oldest file has the largest suffix number** (e.g., `event.log.20` is oldest)

When analyzing logs in a directory, process them **chronologically from oldest to newest**:
1. Sort by suffix number in descending order: `event.log.20` → `event.log.1` → `event.log`
2. Process in that order to maintain proper event sequence

## Log File Format

The scripts process Solace broker event logs with the following structure:
- One entry per line
- ISO 8601 timestamps at the start of each line (e.g., `2026-01-19T18:29:47.818+00:00`)
- Syslog-style log level (e.g., `<local3.info>`)
- Broker name (e.g., `kilo-production-j5m5mqt592d-solace-primary-0`)
- Event types: `CLIENT_CLIENT_CONNECT`, `CLIENT_CLIENT_DISCONNECT`, and others

### Event Log Structure

Full event log lines contain these common fields:
- **Timestamp**: ISO 8601 format with timezone
- **Log level**: Syslog format (e.g., `<local3.info>`)
- **Broker name**: Kubernetes pod name or hostname
- **Event type**: `CLIENT_CLIENT_CONNECT` or `CLIENT_CLIENT_DISCONNECT`
- **VPN name**: Virtual private network identifier (e.g., `iff_prod`)
- **Client name**: Full client identifier (e.g., `atom01.iffprodcloud.awsuse1.boom/2293796/ab8a9e404c7795d00390/1FIjccNfaQ`)
- **Client ID**: Broker-assigned unique ID per connection (e.g., `Client (461)`)
- **Username**: Authentication username
- **Client version**: API version (e.g., `version(10.28.1)`)
- **Platform**: Client API platform and runtime details
- **SSL details**: TLS version, cipher suite, etc.

### Connection Event Patterns

**CLIENT_CLIENT_CONNECT events** contain:
- `connected to <broker-ip>:<broker-port>` - The broker endpoint
- `from <client-ip>:<client-port>` - The client source endpoint (e.g., `from 172.16.35.145:45728`)
- `version(...)` - Client API version
- `platform(...)` - Client platform details (OS, runtime, SDK)
- `APIuser(...)` - Client description including computer name and process ID
- `authScheme(...)` - Authentication method (e.g., `Basic`)
- `clientProfile(...)` and `ACLProfile(...)` - Broker policy assignments
- SSL/TLS details if encrypted

**CLIENT_CLIENT_DISCONNECT events** contain:
- `reason(...)` - Disconnect reason (e.g., `Peer TCP Closed`, `Peer TCP Reset`)
- `final statistics - dp(...)` - 22-field dataplane statistics tuple:
  - Fields 1-6: Message counts (control RX/TX, topic RX/TX, total RX/TX)
  - Fields 7-12: Byte counts (control RX/TX, topic RX/TX, total RX/TX)
  - Fields 13-16: Message rates (current ingress/egress, average ingress/egress)
  - Fields 17-22: Denial/discard counts (duplicates, no subscription match, parse errors, message too big, transmit congestion)
- `conn(...)` - Connection tuple with format `conn(0, 0, <client-ip>:<client-port>, <state>, 0, 0, 0)`
  - **Third field** is the client IP:port (critical for matching connect/disconnect pairs)
  - **Fourth field** is connection state (e.g., `ESTAB`, `CLSWT`)
- `zip(...)` - Compression statistics
- `web(...)` - Web transport statistics
- **Orphaned disconnects**: Disconnects without a matching prior connect (based on `ip:port`) are ignored

## Architecture

### ConnectionTracker Class

The core analyzer (`analyze_client_connections.py`) uses a `ConnectionTracker` class that:

1. **Tracks active connections**: Maintains a dictionary mapping `ip:port` endpoints to their source IP and connection timestamp
2. **Collects per-IP statistics**: Uses `defaultdict` to accumulate metrics for each unique source IP:
   - Total connection count
   - Connection duration list (calculated from paired connect/disconnect events)
   - TCP reset count
   - Concurrent connection samples (taken at connect and disconnect times)

3. **Processes log lines sequentially**:
   - Extracts timestamps with regex
   - Routes to `process_connect()` or `process_disconnect()` based on event type
   - Matches disconnects to connects using the `ip:port` endpoint as a key

4. **Generates reports**: Produces formatted output sorted by total connections (descending)

### Key Design Decisions

- **Endpoint-based matching**: Uses full `ip:port` as the key to match connect/disconnect pairs, but reports statistics aggregated by IP only
- **Concurrent connection sampling**: Since the script processes events sequentially, it samples concurrent connection count at each connect/disconnect event rather than maintaining continuous time-series data
- **Graceful degradation**: Skips malformed lines and unmatched disconnects rather than failing

### ReconnectionTracker Class

The reconnection analyzer (`analyze_client_reconnects.py`) uses a `ReconnectionTracker` class that:

1. **Tracks client lifecycle by client name**: Maintains state for connected clients and their last disconnect
   - `connected_clients`: Currently connected clients with their connect timestamp
   - `last_disconnect`: Last disconnect event per client with timestamp and reason

2. **Detects reconnections**: When a client connects and has a previous disconnect in history, it's counted as a reconnection

3. **Categorizes by disconnect reason**: Tracks three disconnect reason types:
   - `tcp_reset`: Matches "Peer TCP Reset" or "Peer TCP reset"
   - `tcp_closed`: Matches "Peer TCP Closed" or "Peer TCP closed"
   - `other`: Any other disconnect reason

4. **Calculates reconnection timing**: Measures time from disconnect to next connect for each reconnection

5. **Processes logs chronologically**: Uses `find_and_sort_log_files()` to discover and sort rotated logs:
   - Finds all `event.log*` files in the directory
   - Sorts with highest suffix first: `event.log.20` → `event.log.1` → `event.log`
   - Processes them in order to maintain proper client state across log rotations

6. **Reports statistics**:
   - Total reconnect count
   - Reconnects by disconnect reason (TCP reset vs. TCP closed)
   - Min/max/average time to reconnect
