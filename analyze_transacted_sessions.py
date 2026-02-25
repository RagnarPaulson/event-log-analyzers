#!/usr/bin/env python3
"""
Analyze Solace event logs for transacted session usage.

Tracks transacted sessions within connections and reports:
- Max/average transacted sessions per connection
- Concurrent vs serial session usage
- Transaction statistics (commits, rollbacks, messages)
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


class TransactedSessionAnalyzer:
    """Analyze transacted session usage within connections."""

    def __init__(self):
        # Track active connections: client_id -> {connect_time, client_name, endpoint}
        self.active_connections = {}

        # Track active transacted sessions: (client_id, session_id) -> open_time
        self.active_sessions = {}

        # Per-connection statistics: client_id -> {session_count, sessions: [], concurrent_detected: bool}
        self.connection_stats = defaultdict(lambda: {
            'client_name': None,
            'session_count': 0,
            'sessions': [],  # List of {open_time, close_time, duration, commits, rollbacks, published, consumed}
            'max_concurrent': 0,
            'concurrent_detected': False
        })

        # Transaction statistics
        self.total_sessions = 0
        self.total_commits = 0
        self.total_rollbacks = 0
        self.total_failed = 0
        self.total_published = 0
        self.total_consumed = 0

        # Event counts
        self.events_processed = {
            'connects': 0,
            'disconnects': 0,
            'session_opens': 0,
            'session_closes': 0
        }

        # Time range
        self.first_timestamp = None
        self.last_timestamp = None
        self.total_lines = 0

    def extract_client_id(self, line):
        """Extract Client (ID) from line."""
        match = re.search(r'Client \((\d+)\)', line)
        if match:
            return match.group(1)
        return None

    def extract_client_name(self, line):
        """Extract client name from line."""
        # Pattern: After VPN, the next token is client name
        match = re.search(r'iff_prod\s+(\S+)', line)
        if match:
            return match.group(1)
        return None

    def extract_transacted_session_id(self, line):
        """Extract Transacted Session (ID) from line."""
        match = re.search(r'Transacted Session \((\d+)\)', line)
        if match:
            return match.group(1)
        return None

    def extract_endpoint(self, line):
        """Extract client ip:port from CONNECT line."""
        match = re.search(r'from ([\d\.]+:\d+)', line)
        if match:
            return match.group(1)
        return None

    def process_connect(self, line, timestamp):
        """Process CLIENT_CLIENT_CONNECT event."""
        client_id = self.extract_client_id(line)
        client_name = self.extract_client_name(line)
        endpoint = self.extract_endpoint(line)

        if client_id:
            self.active_connections[client_id] = {
                'connect_time': timestamp,
                'client_name': client_name,
                'endpoint': endpoint
            }
            self.events_processed['connects'] += 1

    def process_disconnect(self, line, timestamp):
        """Process CLIENT_CLIENT_DISCONNECT event."""
        client_id = self.extract_client_id(line)

        if client_id and client_id in self.active_connections:
            # Remove connection
            del self.active_connections[client_id]
            self.events_processed['disconnects'] += 1

    def process_session_open(self, line, timestamp):
        """Process CLIENT_CLIENT_TRANSACTED_SESSION_OPEN event."""
        client_id = self.extract_client_id(line)
        session_id = self.extract_transacted_session_id(line)
        client_name = self.extract_client_name(line)

        if not client_id or not session_id:
            return

        # Track active session
        session_key = (client_id, session_id)
        self.active_sessions[session_key] = timestamp

        # Update connection stats
        if client_name:
            self.connection_stats[client_id]['client_name'] = client_name

        self.connection_stats[client_id]['session_count'] += 1

        # Check for concurrent sessions
        concurrent_count = sum(1 for (cid, sid) in self.active_sessions.keys() if cid == client_id)
        if concurrent_count > 1:
            self.connection_stats[client_id]['concurrent_detected'] = True

        # Track max concurrent for this connection
        current_max = self.connection_stats[client_id]['max_concurrent']
        self.connection_stats[client_id]['max_concurrent'] = max(current_max, concurrent_count)

        self.events_processed['session_opens'] += 1
        self.total_sessions += 1

    def process_session_close(self, line, timestamp):
        """Process CLIENT_CLIENT_TRANSACTED_SESSION_CLOSE event."""
        client_id = self.extract_client_id(line)
        session_id = self.extract_transacted_session_id(line)

        if not client_id or not session_id:
            return

        session_key = (client_id, session_id)

        # Extract statistics
        commit_match = re.search(r'commits (\d+)', line)
        rollback_match = re.search(r'rollback (\d+)', line)
        failed_match = re.search(r'failed (\d+)', line)
        published_match = re.search(r'published (\d+)', line)
        consumed_match = re.search(r'consumed (\d+)', line)

        commits = int(commit_match.group(1)) if commit_match else 0
        rollbacks = int(rollback_match.group(1)) if rollback_match else 0
        failed = int(failed_match.group(1)) if failed_match else 0
        published = int(published_match.group(1)) if published_match else 0
        consumed = int(consumed_match.group(1)) if consumed_match else 0

        # Update totals
        self.total_commits += commits
        self.total_rollbacks += rollbacks
        self.total_failed += failed
        self.total_published += published
        self.total_consumed += consumed

        # Calculate duration if we have the open event
        if session_key in self.active_sessions:
            open_time = self.active_sessions[session_key]
            duration = (timestamp - open_time).total_seconds()

            # Store session info
            self.connection_stats[client_id]['sessions'].append({
                'open_time': open_time.isoformat(),
                'close_time': timestamp.isoformat(),
                'duration': duration,
                'commits': commits,
                'rollbacks': rollbacks,
                'failed': failed,
                'published': published,
                'consumed': consumed
            })

            # Remove from active
            del self.active_sessions[session_key]

        self.events_processed['session_closes'] += 1

    def process_line(self, line):
        """Process a single log line."""
        self.total_lines += 1

        if len(line) < 29:
            return

        timestamp_str = line[:29]

        # Track time range
        if not self.first_timestamp:
            self.first_timestamp = timestamp_str
        self.last_timestamp = timestamp_str

        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except ValueError:
            return

        # Route to appropriate handler
        if 'CLIENT_CLIENT_CONNECT' in line:
            self.process_connect(line, timestamp)
        elif 'CLIENT_CLIENT_DISCONNECT' in line:
            self.process_disconnect(line, timestamp)
        elif 'CLIENT_CLIENT_TRANSACTED_SESSION_OPEN' in line:
            self.process_session_open(line, timestamp)
        elif 'CLIENT_CLIENT_TRANSACTED_SESSION_CLOSE' in line:
            self.process_session_close(line, timestamp)

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
        print("TRANSACTED SESSION ANALYSIS REPORT")
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
                print(f"Error calculating duration: {e}")

        # Event processing stats
        print(f"\nEvents Processed:")
        print(f"  Total lines:               {self.total_lines:,}")
        print(f"  CONNECT events:            {self.events_processed['connects']:,}")
        print(f"  DISCONNECT events:         {self.events_processed['disconnects']:,}")
        print(f"  SESSION_OPEN events:       {self.events_processed['session_opens']:,}")
        print(f"  SESSION_CLOSE events:      {self.events_processed['session_closes']:,}")

        # Overall transaction statistics
        print(f"\nTransaction Statistics:")
        print(f"  Total transacted sessions: {self.total_sessions:,}")
        print(f"  Total commits:             {self.total_commits:,}")
        print(f"  Total rollbacks:           {self.total_rollbacks:,}")
        print(f"  Total failed:              {self.total_failed:,}")
        print(f"  Total messages published:  {self.total_published:,}")
        print(f"  Total messages consumed:   {self.total_consumed:,}")

        # Connection-level statistics
        connections_with_sessions = {cid: stats for cid, stats in self.connection_stats.items()
                                     if stats['session_count'] > 0}

        if connections_with_sessions:
            session_counts = [stats['session_count'] for stats in connections_with_sessions.values()]
            avg_sessions = sum(session_counts) / len(session_counts)
            max_sessions = max(session_counts)

            concurrent_connections = sum(1 for stats in connections_with_sessions.values()
                                        if stats['concurrent_detected'])

            print(f"\nConnection-Level Statistics:")
            print(f"  Connections with transacted sessions: {len(connections_with_sessions):,}")
            print(f"  Max sessions per connection:          {max_sessions}")
            print(f"  Avg sessions per connection:          {avg_sessions:.2f}")
            print(f"  Connections with concurrent sessions: {concurrent_connections}")

        # Detailed breakdown of connections with concurrent sessions
        concurrent_conns = {cid: stats for cid, stats in connections_with_sessions.items()
                           if stats['concurrent_detected']}

        if concurrent_conns:
            print(f"\n{'='*100}")
            print("CONNECTIONS WITH CONCURRENT TRANSACTED SESSIONS")
            print("="*100)

            for client_id, stats in sorted(concurrent_conns.items(),
                                          key=lambda x: x[1]['max_concurrent'],
                                          reverse=True):
                print(f"\nClient ID: {client_id}")
                print(f"  Client Name:        {stats['client_name']}")
                print(f"  Total Sessions:     {stats['session_count']}")
                print(f"  Max Concurrent:     {stats['max_concurrent']}")
                print(f"  Sessions:")
                for i, session in enumerate(stats['sessions'], 1):
                    print(f"    Session {i}:")
                    print(f"      Open:      {session['open_time']}")
                    print(f"      Close:     {session['close_time']}")
                    print(f"      Duration:  {session['duration']:.2f}s")
                    print(f"      Commits:   {session['commits']}, Rollbacks: {session['rollbacks']}")
                    print(f"      Published: {session['published']}, Consumed: {session['consumed']}")

        # Connections with multiple serial sessions
        serial_multi = {cid: stats for cid, stats in connections_with_sessions.items()
                       if stats['session_count'] > 1 and not stats['concurrent_detected']}

        if serial_multi:
            print(f"\n{'='*100}")
            print("CONNECTIONS WITH MULTIPLE SERIAL TRANSACTED SESSIONS (Top 10)")
            print("="*100)

            sorted_serial = sorted(serial_multi.items(),
                                  key=lambda x: x[1]['session_count'],
                                  reverse=True)[:10]

            for client_id, stats in sorted_serial:
                print(f"\nClient ID: {client_id}")
                print(f"  Client Name:        {stats['client_name']}")
                print(f"  Total Sessions:     {stats['session_count']}")
                print(f"  Session Pattern:    Serial (no overlap detected)")


def main():
    if len(sys.argv) != 2:
        print("Usage: ./analyze_transacted_sessions.py <log_file_or_directory>")
        print("\nAnalyzes Solace event logs for transacted session usage.")
        print("Reports max/avg sessions per connection and detects concurrent vs serial usage.")
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
    analyzer = TransactedSessionAnalyzer()
    analyzer.process_files(log_files)

    # Generate report
    analyzer.generate_report()


if __name__ == '__main__':
    main()
