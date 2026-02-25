# Parsing Patterns for Solace Event Logs

Common regex patterns and parsing strategies for extracting data from Solace event logs.

## Timestamp Extraction

```python
# Extract ISO 8601 timestamp (first 29 characters)
timestamp = line[:29]

# Parse to datetime object
from datetime import datetime
dt = datetime.fromisoformat(timestamp)
```

## CLIENT_CLIENT_CONNECT Event Parsing

```python
if 'CLIENT_CLIENT_CONNECT' in line:
    # Extract client endpoint (critical for matching)
    match = re.search(r'from ([\d\.]+):(\d+)', line)
    if match:
        client_ip = match.group(1)
        client_port = match.group(2)
        endpoint = f"{client_ip}:{client_port}"

    # Extract VPN name
    vpn_match = re.search(r'VPN (\S+)', line)
    if vpn_match:
        vpn = vpn_match.group(1)

    # Extract client name
    client_match = re.search(r'Client\((\d+)\)\s+(\S+)', line)
    if client_match:
        client_id = client_match.group(1)
        client_name = client_match.group(2)

    # Extract version
    version_match = re.search(r'version\(([^)]+)\)', line)
    if version_match:
        version = version_match.group(1)

    # Extract platform
    platform_match = re.search(r'platform\(([^)]+)\)', line)
    if platform_match:
        platform = platform_match.group(1)

    # Extract auth scheme
    auth_match = re.search(r'authScheme\(([^)]+)\)', line)
    if auth_match:
        auth_scheme = auth_match.group(1)

    # Extract username
    user_match = re.search(r'user\(([^)]+)\)', line)
    if user_match:
        username = user_match.group(1)
```

## CLIENT_CLIENT_DISCONNECT Event Parsing

```python
if 'CLIENT_CLIENT_DISCONNECT' in line:
    # Extract timestamp
    timestamp = line[:29]

    # Extract endpoint from conn(...) tuple (third field)
    conn_match = re.search(r'conn\([^,]+,\s*[^,]+,\s*([\d\.]+:\d+)', line)
    if conn_match:
        endpoint = conn_match.group(1)

    # Extract disconnect reason
    reason_match = re.search(r'reason\(([^)]+)\)', line)
    if reason_match:
        reason = reason_match.group(1)

    # Extract dataplane statistics
    dp_match = re.search(r'dp\(([^)]+)\)', line)
    if dp_match:
        dp_fields = dp_match.group(1).split(',')
        # dp_fields[0-21] contain the 22 statistics values
        # Fields 1-6: Message counts
        # Fields 7-12: Byte counts
        # Fields 13-16: Message rates
        # Fields 17-22: Denial/discard counts

    # Extract connection state from conn(...) tuple (fourth field)
    state_match = re.search(r'conn\([^,]+,\s*[^,]+,\s*[^,]+,\s*([^,]+)', line)
    if state_match:
        conn_state = state_match.group(1)
```

## Categorizing Disconnect Reasons

```python
def categorize_disconnect_reason(reason):
    """Categorize disconnect reason into tcp_reset, tcp_closed, or other."""
    if 'TCP Reset' in reason or 'TCP reset' in reason:
        return 'tcp_reset'
    elif 'TCP Closed' in reason or 'TCP closed' in reason:
        return 'tcp_closed'
    else:
        return 'other'
```

## Processing Rotated Log Files

```python
import os
import re

def find_and_sort_log_files(directory):
    """Find and sort log files chronologically (oldest first)."""
    log_files = []

    for filename in os.listdir(directory):
        if filename.startswith('event.log'):
            # Extract suffix number (0 for event.log)
            if filename == 'event.log':
                suffix = 0
            else:
                match = re.match(r'event\.log\.(\d+)', filename)
                if match:
                    suffix = int(match.group(1))
                else:
                    continue

            log_files.append((suffix, filename))

    # Sort by suffix descending (largest/oldest first)
    log_files.sort(key=lambda x: x[0], reverse=True)

    return [os.path.join(directory, f[1]) for f in log_files]
```

## Calculating Durations

```python
from datetime import datetime

def calculate_duration(connect_time, disconnect_time):
    """Calculate duration in seconds between two ISO 8601 timestamps."""
    start = datetime.fromisoformat(connect_time)
    end = datetime.fromisoformat(disconnect_time)
    return (end - start).total_seconds()
```

## Graceful Error Handling

```python
def process_line(line):
    """Process a log line with error handling."""
    try:
        # Extract timestamp
        if len(line) < 29:
            return None  # Line too short, skip

        timestamp = line[:29]

        # Validate timestamp format
        try:
            datetime.fromisoformat(timestamp)
        except ValueError:
            return None  # Invalid timestamp, skip

        # Process event type
        if 'CLIENT_CLIENT_CONNECT' in line:
            return process_connect(line, timestamp)
        elif 'CLIENT_CLIENT_DISCONNECT' in line:
            return process_disconnect(line, timestamp)
        else:
            return None  # Not a relevant event

    except Exception as e:
        # Log error if needed, but don't crash
        # print(f"Error processing line: {e}")
        return None
```
