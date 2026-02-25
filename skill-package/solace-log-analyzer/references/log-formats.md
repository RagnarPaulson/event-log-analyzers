# Solace Event Log Formats

Complete specifications for Solace broker event logs.

## Table of Contents
- [General Structure](#general-structure)
- [CLIENT_CLIENT_CONNECT Events](#client_client_connect-events)
- [CLIENT_CLIENT_DISCONNECT Events](#client_client_disconnect-events)
- [Event Matching Strategy](#event-matching-strategy)

## General Structure

### Log File Rotation

Event logs are rotated based on maximum size:
- Current log: `event.log` (newest)
- Rotated logs: `event.log.1`, `event.log.2`, ..., `event.log.N`
- **Oldest file has the largest suffix number** (e.g., `event.log.20` is oldest)

**IMPORTANT**: When analyzing logs in a directory, process them **chronologically from oldest to newest**:
1. Sort by suffix number in descending order: `event.log.20` → `event.log.1` → `event.log`
2. Process in that order to maintain proper event sequence

### Common Event Structure

All event log lines follow this structure:
- One entry per line
- ISO 8601 timestamps at the start of each line (e.g., `2026-01-19T18:29:47.818+00:00`)
- Syslog-style log level (e.g., `<local3.info>`)
- Broker name (e.g., `kilo-production-j5m5mqt592d-solace-primary-0`)
- Event type keyword (e.g., `CLIENT_CLIENT_CONNECT`, `CLIENT_CLIENT_DISCONNECT`)

## CLIENT_CLIENT_CONNECT Events

**Purpose**: Logged when a client establishes a connection to the broker.

### Common Fields

- **Timestamp**: ISO 8601 format with timezone
- **Log level**: Syslog format (e.g., `<local3.info>`)
- **Broker name**: Kubernetes pod name or hostname
- **Event type**: `CLIENT_CLIENT_CONNECT`
- **VPN name**: Virtual private network identifier (e.g., `iff_prod`)
- **Client name**: Full client identifier (e.g., `atom01.iffprodcloud.awsuse1.boom/2293796/ab8a9e404c7795d00390/1FIjccNfaQ`)
- **Client ID**: Broker-assigned unique ID per connection (e.g., `Client (461)`)
- **Username**: Authentication username

### Connection Details

- `connected to <broker-ip>:<broker-port>` - The broker endpoint the client connected to
- `from <client-ip>:<client-port>` - The client source endpoint (e.g., `from 172.16.35.145:45728`)
  - **CRITICAL**: This `<client-ip>:<client-port>` is the key for matching connect/disconnect pairs

### Client Information

- `version(...)` - Client API version (e.g., `version(10.28.1)`)
- `platform(...)` - Client platform details: OS, runtime, SDK
  - Example: `platform(Linux 6.8.0-1018-azure, x86_64, JVM 1.8.0_432 (Oracle Corporation), JCSMP 10.28.1)`
- `APIuser(...)` - Client description including computer name and process ID
- `authScheme(...)` - Authentication method (e.g., `Basic`, `Certificate`, `Kerberos`)
- `clientProfile(...)` - Broker-assigned client profile for permissions
- `ACLProfile(...)` - Broker-assigned ACL profile for authorization

### Security Details

If encrypted connection:
- SSL/TLS version
- Cipher suite
- Certificate details

## CLIENT_CLIENT_DISCONNECT Events

**Purpose**: Logged when a client disconnects from the broker.

### Disconnect Reason

- `reason(...)` - Why the connection ended
  - Common values: `Peer TCP Closed`, `Peer TCP Reset`, `Client Initiated`, `Admin Initiated`
  - **Note**: Case variations exist: `Peer TCP reset` vs `Peer TCP Reset`

### Connection Identification

- `conn(...)` - Connection tuple with format `conn(0, 0, <client-ip>:<client-port>, <state>, 0, 0, 0)`
  - **CRITICAL**: The **third field** (`<client-ip>:<client-port>`) must match the `from` field in the corresponding CONNECT event
  - **Fourth field**: Connection state (e.g., `ESTAB`, `CLSWT`)
  - Use this to pair disconnect events with their connect events

### Dataplane Statistics

- `final statistics - dp(...)` - 22-field comma-separated tuple containing:
  - **Fields 1-6**: Message counts (control RX/TX, topic RX/TX, total RX/TX)
  - **Fields 7-12**: Byte counts (control RX/TX, topic RX/TX, total RX/TX)
  - **Fields 13-16**: Message rates (current ingress/egress, average ingress/egress)
  - **Fields 17-22**: Denial/discard counts
    - Duplicates
    - No subscription match
    - Parse errors
    - Message too big
    - Transmit congestion
    - Other discards

### Other Statistics

- `zip(...)` - Compression statistics (if compression enabled)
- `web(...)` - Web transport statistics (if using WebSocket/REST)

### Orphaned Disconnects

- Disconnects without a matching prior connect (based on `ip:port` endpoint) should be ignored
- This can happen if the connect occurred before the log window being analyzed

## Event Matching Strategy

### Correlating Connect and Disconnect Events

1. Use `<client-ip>:<client-port>` as the matching key
   - From CONNECT: Extract from `from <ip>:<port>`
   - From DISCONNECT: Extract from third field of `conn(..., ..., <ip>:<port>, ...)`

2. Store active connections in a dictionary keyed by endpoint
   ```python
   active_connections = {}  # endpoint -> {timestamp, ip, ...}
   ```

3. When processing CONNECT: Add to dictionary
4. When processing DISCONNECT: Look up and remove from dictionary, calculate duration

5. Handle edge cases:
   - Disconnect without connect: Ignore (logged before analysis window)
   - Connect without disconnect: Connection still active at end of analysis

### Tracking by Client Name vs IP

- **By IP:port** - Use for connection-level metrics (duration, concurrency, resets)
- **By client name** - Use for client lifecycle tracking (reconnections across different IPs)
