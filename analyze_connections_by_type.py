#!/usr/bin/env python3
"""
Analyze Solace event logs to categorize connections as publishers or consumers.

Connections followed by OPEN_FLOW are publishers.
Connections followed by BIND_SUCCESS are consumers.

Reports connections per day and duration statistics, broken down by:
- Overall
- Publishers
- Consumers
- Unknown (neither OPEN_FLOW nor BIND_SUCCESS observed)
"""

import sys
import os
import re
from datetime import datetime
from collections import defaultdict


def find_and_sort_log_files(directory):
    """Find and sort log files chronologically (oldest first)."""
    log_files = []

    for filename in os.listdir(directory):
        if filename.startswith('event.log'):
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


class ConnectionAnalyzer:
    """Analyze Solace connections by type (publisher/consumer)."""

    def __init__(self):
        # Track active connections: endpoint -> {connect_time, ip, client_id}
        self.active_connections = {}

        # Track client types: client_id -> 'publisher' | 'consumer' | 'unknown'
        self.client_types = {}

        # Statistics per IP and type
        # ip -> type -> {count, durations: [], tcp_resets: int}
        self.stats = defaultdict(lambda: defaultdict(lambda: {
            'count': 0,
            'durations': [],
            'tcp_resets': 0,
            'days': set()
        }))

        # Overall tracking
        self.first_timestamp = None
        self.last_timestamp = None
        self.total_lines = 0
        self.events_processed = {
            'connects': 0,
            'disconnects': 0,
            'open_flow': 0,
            'bind': 0
        }

    def extract_endpoint(self, line):
        """Extract client ip:port from line."""
        # For CONNECT: from <ip>:<port>
        if 'CLIENT_CLIENT_CONNECT' in line:
            match = re.search(r'from ([\d\.]+):(\d+)', line)
            if match:
                return f"{match.group(1)}:{match.group(2)}"

        # For DISCONNECT: conn(..., ..., <ip>:<port>, ...)
        elif 'CLIENT_CLIENT_DISCONNECT' in line:
            match = re.search(r'conn\([^,]+,\s*[^,]+,\s*([\d\.]+:\d+)', line)
            if match:
                return match.group(1)

        return None

    def extract_client_id(self, line):
        """Extract Client (ID) from line."""
        match = re.search(r'Client \((\d+)\)', line)
        if match:
            return match.group(1)
        return None

    def process_connect(self, line, timestamp):
        """Process CLIENT_CLIENT_CONNECT event."""
        endpoint = self.extract_endpoint(line)
        client_id = self.extract_client_id(line)

        if not endpoint:
            return

        ip = endpoint.split(':')[0]

        self.active_connections[endpoint] = {
            'connect_time': timestamp,
            'ip': ip,
            'client_id': client_id
        }

        # Initialize client type as unknown
        if client_id and client_id not in self.client_types:
            self.client_types[client_id] = 'unknown'

        self.events_processed['connects'] += 1

    def process_open_flow(self, line, timestamp):
        """Process CLIENT_CLIENT_OPEN_FLOW event - indicates publisher."""
        client_id = self.extract_client_id(line)

        if client_id:
            self.client_types[client_id] = 'publisher'
            self.events_processed['open_flow'] += 1

    def process_bind(self, line, timestamp):
        """Process CLIENT_CLIENT_BIND_SUCCESS event - indicates consumer."""
        client_id = self.extract_client_id(line)

        if client_id:
            self.client_types[client_id] = 'consumer'
            self.events_processed['bind'] += 1

    def process_disconnect(self, line, timestamp):
        """Process CLIENT_CLIENT_DISCONNECT event."""
        endpoint = self.extract_endpoint(line)

        if not endpoint or endpoint not in self.active_connections:
            return

        conn_info = self.active_connections.pop(endpoint)
        ip = conn_info['ip']
        client_id = conn_info['client_id']

        # Determine connection type
        conn_type = self.client_types.get(client_id, 'unknown')

        # Calculate duration
        try:
            start = datetime.fromisoformat(conn_info['connect_time'])
            end = datetime.fromisoformat(timestamp)
            duration = (end - start).total_seconds()
        except ValueError:
            return

        # Extract day from timestamp
        day = timestamp.split('T')[0]

        # Check for TCP reset
        is_reset = 'Peer TCP Reset' in line or 'Peer TCP reset' in line

        # Update statistics
        self.stats[ip][conn_type]['count'] += 1
        self.stats[ip][conn_type]['durations'].append(duration)
        self.stats[ip][conn_type]['days'].add(day)
        if is_reset:
            self.stats[ip][conn_type]['tcp_resets'] += 1

        self.events_processed['disconnects'] += 1

    def process_line(self, line):
        """Process a single log line."""
        self.total_lines += 1

        if len(line) < 29:
            return

        timestamp = line[:29]

        # Track time range
        if not self.first_timestamp:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp

        # Route to appropriate handler
        if 'CLIENT_CLIENT_CONNECT' in line:
            self.process_connect(line, timestamp)
        elif 'CLIENT_CLIENT_DISCONNECT' in line:
            self.process_disconnect(line, timestamp)
        elif 'CLIENT_CLIENT_OPEN_FLOW' in line:
            self.process_open_flow(line, timestamp)
        elif 'CLIENT_CLIENT_BIND_SUCCESS' in line:
            self.process_bind(line, timestamp)

    def process_files(self, log_files):
        """Process all log files in chronological order."""
        for log_file in log_files:
            print(f"Processing: {log_file}")
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        self.process_line(line)
            except Exception as e:
                print(f"Error processing {log_file}: {e}")

    def generate_report(self):
        """Generate formatted report."""
        print("\n" + "=" * 100)
        print("SOLACE CONNECTION ANALYSIS BY TYPE (Publisher/Consumer)")
        print("=" * 100)

        # Time range
        if self.first_timestamp and self.last_timestamp:
            try:
                start = datetime.fromisoformat(self.first_timestamp)
                end = datetime.fromisoformat(self.last_timestamp)
                duration = (end - start).total_seconds()
                print(f"\nTime Range:")
                print(f"  First event: {self.first_timestamp}")
                print(f"  Last event:  {self.last_timestamp}")
                print(f"  Duration:    {duration:.2f} seconds ({duration/86400:.2f} days)")
            except Exception as e:
                print(f"Error callculating duration: {e}")

        # Event processing stats
        print(f"\nEvents Processed:")
        print(f"  Total lines:       {self.total_lines:,}")
        print(f"  CONNECT events:    {self.events_processed['connects']:,}")
        print(f"  DISCONNECT events: {self.events_processed['disconnects']:,}")
        print(f"  OPEN_FLOW events:  {self.events_processed['open_flow']:,}")
        print(f"  BIND events:       {self.events_processed['bind']:,}")

        # Active connections at end
        active_by_type = defaultdict(int)
        for endpoint, conn_info in self.active_connections.items():
            client_id = conn_info.get('client_id')
            conn_type = self.client_types.get(client_id, 'unknown')
            active_by_type[conn_type] += 1

        total_active = len(self.active_connections)
        print(f"\nActive Sessions at End of Analysis:")
        print(f"  Total active:      {total_active:,}")
        print(f"  Active publishers: {active_by_type['publisher']:,}")
        print(f"  Active consumers:  {active_by_type['consumer']:,}")
        print(f"  Active unknown:    {active_by_type['unknown']:,}")

        # Calculate overall totals by type
        totals_by_type = defaultdict(lambda: {
            'connections': 0,
            'unique_ips': 0,
            'unique_days': set(),
            'total_duration': 0,
            'tcp_resets': 0
        })

        for ip, type_stats in self.stats.items():
            for conn_type, stats in type_stats.items():
                totals_by_type[conn_type]['connections'] += stats['count']
                totals_by_type[conn_type]['unique_ips'] += 1
                totals_by_type[conn_type]['unique_days'].update(stats['days'])
                totals_by_type[conn_type]['total_duration'] += sum(stats['durations'])
                totals_by_type[conn_type]['tcp_resets'] += stats['tcp_resets']

        # Summary by type
        print(f"\n{'='*100}")
        print("SUMMARY BY CONNECTION TYPE (Completed Sessions)")
        print("="*100)
        print(f"{'Type':<15} {'Completed':<15} {'Unique IPs':<15} {'Unique Days':<15} {'TCP Resets':<15}")
        print("-" * 100)

        for conn_type in ['publisher', 'consumer', 'unknown']:
            if conn_type in totals_by_type:
                stats = totals_by_type[conn_type]
                print(f"{conn_type.capitalize():<15} {stats['connections']:<15,} "
                      f"{stats['unique_ips']:<15} {len(stats['unique_days']):<15} "
                      f"{stats['tcp_resets']:<15}")

        # Detailed breakdown by IP
        print(f"\n{'='*100}")
        print("DETAILED ANALYSIS BY SOURCE IP")
        print("="*100)

        # Collect all IPs with their total connection counts
        ip_totals = []
        for ip, type_stats in self.stats.items():
            total_conns = sum(stats['count'] for stats in type_stats.values())
            ip_totals.append((ip, total_conns, type_stats))

        # Sort by total connections descending
        ip_totals.sort(key=lambda x: x[1], reverse=True)

        # Count active connections per IP and type
        active_per_ip_type = defaultdict(lambda: defaultdict(int))
        for endpoint, conn_info in self.active_connections.items():
            ip = conn_info['ip']
            client_id = conn_info.get('client_id')
            conn_type = self.client_types.get(client_id, 'unknown')
            active_per_ip_type[ip][conn_type] += 1

        for ip, total_conns, type_stats in ip_totals:
            # Calculate total active for this IP
            ip_active = sum(active_per_ip_type.get(ip, {}).values())

            print(f"\nSource IP: {ip} (Total: {total_conns} connections, Active: {ip_active})")
            print("-" * 100)
            print(f"{'Type':<15} {'Completed':<15} {'Active':<10} {'Days':<10} {'Avg Duration':<20} {'TCP Resets':<15}")
            print("-" * 100)

            for conn_type in ['publisher', 'consumer', 'unknown']:
                if conn_type in type_stats or conn_type in active_per_ip_type.get(ip, {}):
                    stats = type_stats.get(conn_type, {'count': 0, 'durations': [], 'days': set(), 'tcp_resets': 0})
                    active_count = active_per_ip_type.get(ip, {}).get(conn_type, 0)
                    avg_duration = sum(stats['durations']) / len(stats['durations']) if stats['durations'] else 0

                    print(f"{conn_type.capitalize():<15} {stats['count']:<15} "
                          f"{active_count:<10} {len(stats['days']):<10} {avg_duration:<20.2f} "
                          f"{stats['tcp_resets']:<15}")


def main():
    if len(sys.argv) != 2:
        print("Usage: ./analyze_connections_by_type.py <log_file_or_directory>")
        print("\nAnalyzes Solace event logs to categorize connections as publishers or consumers.")
        print("Connections followed by OPEN_FLOW are publishers.")
        print("Connections followed by BIND_SUCCESS are consumers.")
        sys.exit(1)

    path = sys.argv[1]

    # Check if path is a file or directory
    if os.path.isfile(path):
        # Single file mode
        log_files = [path]
        print(f"Processing single log file: {os.path.basename(path)}")
    elif os.path.isdir(path):
        # Directory mode - find and sort log files
        log_files = find_and_sort_log_files(path)
        if not log_files:
            print(f"No event.log files found in {path}")
            sys.exit(1)
        print(f"Found {len(log_files)} log file(s)")
    else:
        print(f"Error: {path} is not a valid file or directory")
        sys.exit(1)

    # Create analyzer and process files
    analyzer = ConnectionAnalyzer()
    analyzer.process_files(log_files)

    # Generate report
    analyzer.generate_report()


if __name__ == '__main__':
    main()
