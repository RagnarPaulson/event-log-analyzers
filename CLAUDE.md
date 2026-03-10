# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

**This is a context repository for generating custom log analysis scripts.**

The Python scripts in this directory (`analyze_client_connections.py`, `analyze_client_reconnects.py`) are **reference examples**, not the primary deliverable. The real value is the **log format specifications** below, which enable you to generate custom analyzers for any specific question about Solace event logs.

## How to Use This Context

When a user asks a question about Solace logs:

1. **Read the log format specifications below** to understand the event structure
2. **Generate a custom Python script** that answers their specific question
3. **Use the reference implementations** as architectural examples
4. **Follow the patterns** for parsing, matching events, and reporting

### Supported Event Types

This repository provides specifications and examples for analyzing these Solace broker event types:
- **CLIENT_CLIENT_CONNECT**: Client connection establishment
- **CLIENT_CLIENT_DISCONNECT**: Client disconnection with statistics
- **CLIENT_CLIENT_OPEN_FLOW**: Publisher flow opened (identifies publishing connections)
- **CLIENT_CLIENT_BIND_SUCCESS**: Consumer queue binding (identifies consuming connections)
- **CLIENT_CLIENT_TRANSACTED_SESSION_OPEN**: Transaction session started
- **CLIENT_CLIENT_TRANSACTED_SESSION_CLOSE**: Transaction session completed with commit/rollback statistics

## Extending This Repository

To handle new log types or event formats:

1. **Add new format specifications** to this file with the same level of detail
2. **Include annotated examples** in separate `.txt` files
3. **Optionally create reference implementations** following the existing patterns

### Log Types to Add:
- Other event types (QUEUE, BRIDGE, VPN, etc.)
- Message-level logs (publish/subscribe tracking)
- System metrics logs
- Audit logs
- Performance statistics

## Log File Format: Solace Broker Event Logs

### General Structure

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

### Event Type: CLIENT_CLIENT_CONNECT

**Purpose**: Logged when a client establishes a connection to the broker.

**Common Fields**:
- **Timestamp**: ISO 8601 format with timezone
- **Log level**: Syslog format (e.g., `<local3.info>`)
- **Broker name**: Kubernetes pod name or hostname
- **Event type**: `CLIENT_CLIENT_CONNECT`
- **VPN name**: Virtual private network identifier (e.g., `iff_prod`)
- **Client name**: Full client identifier (e.g., `atom01.iffprodcloud.awsuse1.boom/2293796/ab8a9e404c7795d00390/1FIjccNfaQ`)
- **Client ID**: Broker-assigned unique ID per connection (e.g., `Client (461)`)
- **Username**: Authentication username

**Connection Details**:
- `connected to <broker-ip>:<broker-port>` - The broker endpoint the client connected to
- `from <client-ip>:<client-port>` - The client source endpoint (e.g., `from 172.16.35.145:45728`)
  - **CRITICAL**: This `<client-ip>:<client-port>` is the key for matching connect/disconnect pairs

**Client Information**:
- `version(...)` - Client API version (e.g., `version(10.28.1)`)
- `platform(...)` - Client platform details: OS, runtime, SDK (e.g., `platform(Linux 6.8.0-1018-azure, x86_64, JVM 1.8.0_432 (Oracle Corporation), JCSMP 10.28.1)`)
- `APIuser(...)` - Client description including computer name and process ID
- `authScheme(...)` - Authentication method (e.g., `Basic`, `Certificate`, `Kerberos`)
- `clientProfile(...)` - Broker-assigned client profile for permissions
- `ACLProfile(...)` - Broker-assigned ACL profile for authorization

**Security Details** (if encrypted):
- SSL/TLS version
- Cipher suite
- Certificate details

**Example Pattern for Parsing**:
```python
if 'CLIENT_CLIENT_CONNECT' in line:
    # Extract timestamp
    timestamp = line[:29]  # ISO 8601 format

    # Extract Client ID (PRIMARY matching key)
    client_id_match = re.search(r'Client \((\d+)\)', line)
    if client_id_match:
        client_id = client_id_match.group(1)

    # Extract client endpoint (for IP-based reporting only)
    match = re.search(r'from ([\d\.]+):(\d+)', line)
    if match:
        client_ip = match.group(1)
        client_port = match.group(2)
        endpoint = f"{client_ip}:{client_port}"

    # Extract other fields as needed
    vpn_match = re.search(r'VPN (\S+)', line)
    version_match = re.search(r'version\(([^)]+)\)', line)
```

### Event Type: CLIENT_CLIENT_DISCONNECT

**Purpose**: Logged when a client disconnects from the broker.

**Disconnect Reason**:
- `reason(...)` - Why the connection ended
  - Common values: `Peer TCP Closed`, `Peer TCP Reset`, `Client Initiated`, `Admin Initiated`
  - Case variations exist: `Peer TCP reset` vs `Peer TCP Reset`

**Connection Identification**:
- `Client (ID)` - **PRIMARY MATCHING KEY**: Broker-assigned unique ID per connection (e.g., `Client (461)`)
  - Present in both CONNECT and DISCONNECT events
  - Use for all general-purpose connect/disconnect correlation
  - Note: client-id values may be reused for subsequent connections; use stateful tracking (add on CONNECT, remove on DISCONNECT)
- `conn(...)` - Connection tuple with format `conn(0, 0, <client-ip>:<client-port>, <state>, 0, 0, 0)`
  - **SECONDARY**: The **third field** (`<client-ip>:<client-port>`) is used only when the analysis specifically requires IP-based grouping or reporting
  - **Fourth field**: Connection state (e.g., `ESTAB`, `CLSWT`)

**Dataplane Statistics**:
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

**Other Statistics**:
- `zip(...)` - Compression statistics (if compression enabled)
- `web(...)` - Web transport statistics (if using WebSocket/REST)

**Orphaned Disconnects**:
- Disconnects without a matching prior connect (based on `Client (ID)`) should be ignored
- This can happen if the connect occurred before the log window being analyzed

**Example Pattern for Parsing**:
```python
if 'CLIENT_CLIENT_DISCONNECT' in line:
    # Extract timestamp
    timestamp = line[:29]

    # Extract Client ID (PRIMARY matching key)
    client_id_match = re.search(r'Client \((\d+)\)', line)
    if client_id_match:
        client_id = client_id_match.group(1)

    # Extract endpoint from conn(...) tuple (for IP-based reporting only)
    conn_match = re.search(r'conn\([^,]+,\s*[^,]+,\s*([\d\.]+:\d+)', line)
    if conn_match:
        endpoint = conn_match.group(1)

    # Extract disconnect reason
    reason_match = re.search(r'reason\(([^)]+)\)', line)
    if reason_match:
        reason = reason_match.group(1)

    # Extract dataplane statistics if needed
    dp_match = re.search(r'dp\(([^)]+)\)', line)
    if dp_match:
        dp_fields = dp_match.group(1).split(',')
        # dp_fields[0-21] contain the 22 statistics values
```

## Event Matching Strategy

**To correlate connect and disconnect events**:

**PRIMARY METHOD - Use `Client (ID)` for matching**:
1. Extract `Client (ID)` from both CONNECT and DISCONNECT events
   - From CONNECT: Extract using `re.search(r'Client \((\d+)\)', line)`
   - From DISCONNECT: Extract using the same pattern

2. Store active connections in a dictionary keyed by Client ID
   ```python
   active_connections = {}  # client_id -> {timestamp, ip, client_name, ...}
   ```

3. When processing CONNECT: Add to dictionary using Client ID as key
4. When processing DISCONNECT: Look up by Client ID, remove from dictionary, calculate duration

5. Handle edge cases:
   - Disconnect without connect: Ignore (logged before analysis window)
   - Connect without disconnect: Connection still active at end of analysis

**SECONDARY METHOD - Use `<client-ip>:<client-port>` only for IP-based grouping**:
- When the analysis specifically requires grouping or reporting by source IP
- From CONNECT: Extract from `from <ip>:<port>`
- From DISCONNECT: Extract from third field of `conn(..., ..., <ip>:<port>, ...)`
- Example use case: Aggregate statistics per IP address for reporting

## Reference Implementation: ConnectionTracker

The `analyze_client_connections.py` script demonstrates this pattern:

### Architecture

**Class: ConnectionTracker**

**State Management**:
- `active_connections`: Dict mapping `Client (ID)` → connection metadata (including IP, timestamp, etc.)
- `ip_stats`: Dict mapping source IP → aggregated statistics for reporting

**Core Methods**:
1. `process_connect()`:
   - Extracts `Client (ID)` as primary key
   - Extracts IP from `from` field for reporting
   - Stores in `active_connections` keyed by Client ID
   - Updates concurrent connection count

2. `process_disconnect()`:
   - Extracts `Client (ID)` to match with active connections
   - Looks up connection in `active_connections` by Client ID
   - Calculates duration
   - Updates statistics (total connections, durations, TCP resets)
   - Removes from `active_connections`

3. `generate_report()`:
   - Aggregates statistics per IP
   - Calculates averages
   - Sorts by connection count

**Key Design Decisions**:
- **Client ID-based matching**: Use `Client (ID)` for connect/disconnect correlation, then aggregate by IP for reporting
- **Concurrent connection sampling**: Sample count at each event rather than continuous tracking
- **Graceful degradation**: Skip malformed lines, ignore orphaned disconnects

## Reference Implementation: ReconnectionTracker

The `analyze_client_reconnects.py` script demonstrates tracking client lifecycle:

### Architecture

**Class: ReconnectionTracker**

**State Management**:
- `connected_clients`: Currently connected clients by client name
- `last_disconnect`: Last disconnect event per client (timestamp + reason)

**Core Logic**:
1. Track by **client name** (not IP, since clients may reconnect from different IPs)
2. When client connects:
   - If client has previous disconnect → count as reconnection
   - Calculate time since last disconnect
   - Record connect timestamp

3. When client disconnects:
   - Record disconnect timestamp and reason
   - Categorize reason: `tcp_reset`, `tcp_closed`, `other`

4. Process logs chronologically across rotations using `find_and_sort_log_files()`

**Reconnection Categories**:
- After TCP Reset
- After TCP Closed
- After other disconnect reasons

**Metrics Calculated**:
- Total reconnections
- Reconnections by category
- Min/max/average reconnection time

## Guidelines for Generated Scripts

When generating custom analyzers:

1. **Accept directory or file argument**: REQUIRED - All scripts must accept either a directory path or file path as a command-line argument
2. **Use standard library only**: No external dependencies (datetime, re, sys, os, collections)
3. **Make executable**: Include `#!/usr/bin/env python3` shebang
4. **Handle edge cases**: Malformed lines, missing fields, orphaned events
5. **Provide clear output**: Formatted reports with context and statistics
6. **Sort chronologically**: When processing multiple log files
7. **Document assumptions**: What events are being matched, what's being ignored
8. **Use Client (ID) for matching**: Always use `Client (ID)` as the primary key for correlating CONNECT/DISCONNECT events; only use IP-based fields for grouping/reporting

## Common Analysis Patterns

### Pattern: Aggregate by Field
```python
from collections import defaultdict
stats_by_field = defaultdict(int)
# Count events grouped by VPN, platform, etc.
```

### Pattern: Track State Over Time
```python
active_items = {}  # Track what's currently happening
completed_items = []  # Track what's finished
```

### Pattern: Calculate Durations
```python
from datetime import datetime
start = datetime.fromisoformat(timestamp1)
end = datetime.fromisoformat(timestamp2)
duration = (end - start).total_seconds()
```

### Pattern: Categorize by Matching
```python
if 'TCP Reset' in reason or 'TCP reset' in reason:
    category = 'tcp_reset'
elif 'TCP Closed' in reason or 'TCP closed' in reason:
    category = 'tcp_closed'
```

### Event Type: CLIENT_CLIENT_OPEN_FLOW

**Purpose**: Logged when a client opens a publisher flow (indicates the connection is used for publishing messages).

**Common Fields**:
- **Timestamp**: ISO 8601 format with timezone
- **Event type**: `CLIENT_CLIENT_OPEN_FLOW`
- **VPN name**: Virtual private network identifier
- **Client name**: Full client identifier
- **Client ID**: Broker-assigned unique ID per connection (e.g., `Client (273)`)
- **Username**: Authentication username

**Flow Details**:
- `Pub flow session` - Indicates this is a publisher flow
- `flow name` - Flow identifier
- `transacted session id` - ID if this flow is part of a transaction (or -1 if not transacted)
- `publisher id` - Publisher identifier
- `window size` - Flow control window size

**Usage**: When a CLIENT_CLIENT_CONNECT is followed by CLIENT_CLIENT_OPEN_FLOW, the connection is a **publisher**.

### Event Type: CLIENT_CLIENT_BIND_SUCCESS

**Purpose**: Logged when a client successfully binds to a queue (indicates the connection is used for consuming messages).

**Common Fields**:
- **Timestamp**: ISO 8601 format with timezone
- **Event type**: `CLIENT_CLIENT_BIND_SUCCESS`
- **VPN name**: Virtual private network identifier
- **Client name**: Full client identifier
- **Client ID**: Broker-assigned unique ID per connection (e.g., `Client (70)`)
- **Username**: Authentication username

**Bind Details**:
- `Bind to Durable Queue <queue-name>` - Queue being bound to
- `Topic()` - Topic subscription (if any)
- `Selector(...)` - Message selector filter (if any)
- `AccessType(...)` - Non-Exclusive or Exclusive
- `FlowType(...)` - Consumer type (e.g., Consumer-Redelivery)
- `FlowId(...)` - Flow identifier
- `TransactedSessionId(...)` - ID if this bind is part of a transaction (-1 if not)

**Usage**: When a CLIENT_CLIENT_CONNECT is followed by CLIENT_CLIENT_BIND_SUCCESS, the connection is a **consumer**.

### Event Type: CLIENT_CLIENT_TRANSACTED_SESSION_OPEN

**Purpose**: Logged when a client opens a transacted session within an existing connection.

**Hierarchy**: Transacted sessions exist **within** a connection (between CONNECT and DISCONNECT events).

**Common Fields**:
- **Timestamp**: ISO 8601 format with timezone
- **Event type**: `CLIENT_CLIENT_TRANSACTED_SESSION_OPEN`
- **VPN name**: Virtual private network identifier
- **Client name**: Full client identifier
- **Client ID**: Broker-assigned unique ID per connection (e.g., `Client (449)`)
- **Username**: Authentication username
- **Transacted Session ID**: Broker-assigned unique ID per transacted session (e.g., `Transacted Session (15)`)
- **Session UUID**: Unique identifier for the session (e.g., `f1f415bdf7f04f6b8b228d63ca383503`)

**Key Field for Matching**: `Transacted Session (ID)` - Use this to match OPEN and CLOSE events

**Usage**: Track when transacted sessions start within a connection.

### Event Type: CLIENT_CLIENT_TRANSACTED_SESSION_CLOSE

**Purpose**: Logged when a transacted session closes.

**Common Fields**:
- **Timestamp**: ISO 8601 format with timezone
- **Event type**: `CLIENT_CLIENT_TRANSACTED_SESSION_CLOSE`
- **VPN name**: Virtual private network identifier
- **Client name**: Full client identifier
- **Client ID**: Broker-assigned unique ID per connection
- **Username**: Authentication username
- **Transacted Session ID**: Same ID from the OPEN event (e.g., `Transacted Session (15)`)
- **Session UUID**: Same UUID from the OPEN event

**Transaction Statistics**:
- `requests (commits X, rollback Y, failed Z)` - Transaction outcome counts
- `messages (published X, consumed Y)` - Message counts within the transaction

**Key Field for Matching**: `Transacted Session (ID)` - Must match the corresponding OPEN event

**Session Nesting**: Multiple transacted sessions can exist within a single connection. Sessions may be:
- **Serial**: One session closes before the next opens
- **Concurrent**: Multiple sessions open at the same time on the same connection

**Example Pattern for Parsing**:
```python
if 'CLIENT_CLIENT_TRANSACTED_SESSION_OPEN' in line:
    # Extract Client ID and Transacted Session ID
    client_match = re.search(r'Client \((\d+)\)', line)
    session_match = re.search(r'Transacted Session \((\d+)\)', line)

    if client_match and session_match:
        client_id = client_match.group(1)
        session_id = session_match.group(1)
        # Use combination of client_id + session_id for unique identification

if 'CLIENT_CLIENT_TRANSACTED_SESSION_CLOSE' in line:
    # Extract statistics
    commit_match = re.search(r'commits (\d+)', line)
    rollback_match = re.search(r'rollback (\d+)', line)
    published_match = re.search(r'published (\d+)', line)
    consumed_match = re.search(r'consumed (\d+)', line)
```

## Example Log File Reference

See `annotated-event-log.txt` for complete example log entries with field-by-field annotations for all event types:
- CLIENT_CLIENT_CONNECT
- CLIENT_CLIENT_DISCONNECT
- CLIENT_CLIENT_BIND_SUCCESS (consumer)
- CLIENT_CLIENT_OPEN_FLOW (publisher)
- CLIENT_CLIENT_TRANSACTED_SESSION_OPEN
- CLIENT_CLIENT_TRANSACTED_SESSION_CLOSE

## Questions This Context Should Answer

With these specifications, Claude should be able to generate scripts for questions like:

### Connection Analysis
- "Which IPs have the most connections?"
- "What's the average session length per VPN?"
- "Calculate average session duration by VPN"

### Disconnect Analysis
- "Show clients with high TCP reset rates"
- "Find clients with high TCP reset rates"

### Reconnection Analysis
- "Find clients reconnecting within 5 seconds"
- "Show reconnection patterns for client X"

### Security Analysis
- "Which clients use TLS 1.1 or older?"

### Platform Analysis
- "Break down connections by client SDK version"
- "Do certain platforms have higher disconnect rates?"

### Publisher/Consumer Analysis (using OPEN_FLOW and BIND_SUCCESS events)
- "How many publishers vs consumers per IP?"
- "Identify connections used for publishing vs consuming"

### Transaction Analysis (using TRANSACTED_SESSION_OPEN/CLOSE events)
- "Which connections use the most transacted sessions?"
- "Find connections with concurrent transacted sessions"
- "What's the commit vs rollback ratio?"
- "Show transaction statistics by client"

Each question becomes a custom script generated from these specifications.
