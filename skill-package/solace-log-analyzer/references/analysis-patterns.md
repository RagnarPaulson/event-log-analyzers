# Analysis Patterns for Solace Event Logs

Common patterns for analyzing Solace broker event logs.

## Pattern 1: Aggregate by Field

Count or sum metrics grouped by a specific field (VPN, platform, IP, etc.).

```python
from collections import defaultdict

# Example: Count connections per VPN
vpn_counts = defaultdict(int)

for line in log_file:
    if 'CLIENT_CLIENT_CONNECT' in line:
        vpn_match = re.search(r'VPN (\S+)', line)
        if vpn_match:
            vpn = vpn_match.group(1)
            vpn_counts[vpn] += 1

# Sort and display
for vpn, count in sorted(vpn_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"{vpn}: {count} connections")
```

## Pattern 2: Track State Over Time

Maintain active state and detect transitions.

```python
# Example: Track active connections
active_connections = {}  # endpoint -> {timestamp, ip, client_name, ...}
completed_connections = []  # List of connection records

for line in log_file:
    if 'CLIENT_CLIENT_CONNECT' in line:
        endpoint = extract_endpoint(line)
        timestamp = line[:29]
        active_connections[endpoint] = {
            'connect_time': timestamp,
            'ip': extract_ip(endpoint),
            # ... other fields
        }

    elif 'CLIENT_CLIENT_DISCONNECT' in line:
        endpoint = extract_endpoint(line)
        timestamp = line[:29]

        if endpoint in active_connections:
            conn = active_connections.pop(endpoint)
            conn['disconnect_time'] = timestamp
            conn['duration'] = calculate_duration(conn['connect_time'], timestamp)
            completed_connections.append(conn)
```

## Pattern 3: Calculate Durations and Rates

Measure time between events or calculate rates.

```python
from datetime import datetime

def calculate_metrics(connections):
    """Calculate duration statistics."""
    durations = [c['duration'] for c in connections if 'duration' in c]

    if not durations:
        return {}

    return {
        'min': min(durations),
        'max': max(durations),
        'avg': sum(durations) / len(durations),
        'total': len(durations)
    }
```

## Pattern 4: Filter and Categorize

Group events by categories for comparison.

```python
# Example: Categorize by disconnect reason
from collections import defaultdict

disconnect_categories = defaultdict(list)

for conn in completed_connections:
    if 'disconnect_reason' in conn:
        category = categorize_disconnect_reason(conn['disconnect_reason'])
        disconnect_categories[category].append(conn)

# Report by category
for category, connections in disconnect_categories.items():
    print(f"{category}: {len(connections)} disconnects")
    avg_duration = sum(c['duration'] for c in connections) / len(connections)
    print(f"  Average duration: {avg_duration:.2f}s")
```

## Pattern 5: Detect Reconnections

Identify when a client connects after a previous disconnect.

```python
# Example: Track client reconnections
connected_clients = {}  # client_name -> connect_timestamp
last_disconnect = {}     # client_name -> {timestamp, reason}
reconnections = []

for line in log_file:
    if 'CLIENT_CLIENT_CONNECT' in line:
        client_name = extract_client_name(line)
        timestamp = line[:29]

        # Check if this is a reconnection
        if client_name in last_disconnect:
            reconnect_time = calculate_duration(
                last_disconnect[client_name]['timestamp'],
                timestamp
            )
            reconnections.append({
                'client': client_name,
                'reconnect_time': reconnect_time,
                'previous_reason': last_disconnect[client_name]['reason']
            })

        connected_clients[client_name] = timestamp

    elif 'CLIENT_CLIENT_DISCONNECT' in line:
        client_name = extract_client_name(line)
        timestamp = line[:29]
        reason = extract_reason(line)

        if client_name in connected_clients:
            del connected_clients[client_name]
            last_disconnect[client_name] = {
                'timestamp': timestamp,
                'reason': reason
            }
```

## Pattern 6: Sample Concurrent Connections

Track how many connections are active at each event.

```python
# Example: Track max concurrent connections per IP
from collections import defaultdict

active_by_ip = defaultdict(set)  # ip -> set of endpoints
max_concurrent = defaultdict(int)  # ip -> max concurrent count

for line in log_file:
    if 'CLIENT_CLIENT_CONNECT' in line:
        endpoint = extract_endpoint(line)
        ip = extract_ip(endpoint)

        active_by_ip[ip].add(endpoint)
        max_concurrent[ip] = max(max_concurrent[ip], len(active_by_ip[ip]))

    elif 'CLIENT_CLIENT_DISCONNECT' in line:
        endpoint = extract_endpoint(line)
        ip = extract_ip(endpoint)

        if endpoint in active_by_ip[ip]:
            active_by_ip[ip].remove(endpoint)
```

## Pattern 7: Generate Formatted Reports

Produce clear, sorted output with statistics.

```python
def generate_report(ip_stats):
    """Generate a formatted report sorted by connection count."""
    # Sort by total connections (descending)
    sorted_ips = sorted(ip_stats.items(),
                       key=lambda x: x[1]['total_connections'],
                       reverse=True)

    print(f"{'Source IP':<20} {'Connections':<12} {'Avg Duration':<15} "
          f"{'Max Concurrent':<15} {'TCP Resets':<12}")
    print("-" * 80)

    for ip, stats in sorted_ips:
        avg_duration = (sum(stats['durations']) / len(stats['durations'])
                       if stats['durations'] else 0)

        print(f"{ip:<20} {stats['total_connections']:<12} "
              f"{avg_duration:<15.2f} {stats['max_concurrent']:<15} "
              f"{stats['tcp_resets']:<12}")
```

## Pattern 8: Multi-Pass Analysis

Process logs multiple times for different metrics.

```python
# Pass 1: Collect all events
events = []
for line in log_file:
    if 'CLIENT_CLIENT_CONNECT' in line or 'CLIENT_CLIENT_DISCONNECT' in line:
        events.append(parse_event(line))

# Pass 2: Match connect/disconnect pairs
connections = match_events(events)

# Pass 3: Analyze patterns
reconnections = find_reconnections(connections)
problem_clients = find_frequent_disconnects(connections)
```
