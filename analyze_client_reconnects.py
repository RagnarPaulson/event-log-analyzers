#!/usr/bin/env python3
"""
Log file analyzer for client reconnection patterns.
Processes rotated event logs in chronological order to track when clients
disconnect and reconnect, categorized by disconnect reason.
"""

import re
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class ReconnectionTracker:
    def __init__(self):
        # Track last disconnect per client: key = client_name, value = (disconnect_timestamp, reason)
        self.last_disconnect: Dict[str, Tuple[datetime, str]] = {}

        # Track currently connected clients: key = client_name, value = connect_timestamp
        self.connected_clients: Dict[str, datetime] = {}

        # Connection statistics
        self.total_connections = 0
        self.total_disconnects = 0
        self.total_tcp_resets = 0
        self.total_tcp_closed = 0

        # Reconnection statistics
        self.total_reconnects = 0
        self.reconnects_after_tcp_reset = 0
        self.reconnects_after_tcp_closed = 0
        self.reconnect_times: List[float] = []  # Time in seconds from disconnect to reconnect

        # Event parsing statistics
        self.connect_events_seen = 0
        self.disconnect_events_seen = 0
        self.ignored_connect_no_timestamp = 0
        self.ignored_connect_no_client_name = 0
        self.ignored_disconnect_no_timestamp = 0
        self.ignored_disconnect_no_client_name = 0
        self.ignored_disconnect_no_matching_connect = 0

        # Time range tracking
        self.first_timestamp: Optional[datetime] = None
        self.last_timestamp: Optional[datetime] = None

    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse ISO 8601 timestamp."""
        try:
            return datetime.fromisoformat(timestamp_str.replace('+00:00', '+00:00'))
        except Exception as e:
            print(f"Warning: Failed to parse timestamp '{timestamp_str}': {e}", file=sys.stderr)
            return None

    def extract_client_name(self, line: str, event_type: str) -> Optional[str]:
        """Extract client name from event line."""
        # Pattern: After event type and VPN, the next token is the client name
        # Example: CLIENT_CLIENT_CONNECT: iff_prod atom01.iff...
        pattern = rf'{event_type}:\s+\S+\s+(\S+)'
        match = re.search(pattern, line)
        if match:
            return match.group(1)
        return None

    def extract_disconnect_reason(self, line: str) -> str:
        """Extract disconnect reason from disconnect event."""
        # Pattern: reason(...)
        match = re.search(r'reason\(([^)]+)\)', line)
        if match:
            reason = match.group(1)
            # Normalize the reason
            if 'TCP Reset' in reason or 'TCP reset' in reason:
                return 'tcp_reset'
            elif 'TCP Closed' in reason or 'TCP closed' in reason:
                return 'tcp_closed'
            else:
                return 'other'
        return 'unknown'

    def process_connect(self, timestamp: datetime, line: str):
        """Process CLIENT_CLIENT_CONNECT entry."""
        self.connect_events_seen += 1

        client_name = self.extract_client_name(line, 'CLIENT_CLIENT_CONNECT')
        if not client_name:
            self.ignored_connect_no_client_name += 1
            return

        # Count total connections
        self.total_connections += 1

        # Check if this is a reconnect (client was previously disconnected)
        if client_name in self.last_disconnect:
            disconnect_time, disconnect_reason = self.last_disconnect[client_name]

            # Calculate reconnection time
            reconnect_time = (timestamp - disconnect_time).total_seconds()
            self.reconnect_times.append(reconnect_time)

            # Count total reconnects
            self.total_reconnects += 1

            # Count by disconnect reason
            if disconnect_reason == 'tcp_reset':
                self.reconnects_after_tcp_reset += 1
            elif disconnect_reason == 'tcp_closed':
                self.reconnects_after_tcp_closed += 1

            # Remove from last_disconnect since we've processed this reconnect
            del self.last_disconnect[client_name]

        # Track this connection
        self.connected_clients[client_name] = timestamp

    def process_disconnect(self, timestamp: datetime, line: str):
        """Process CLIENT_CLIENT_DISCONNECT entry."""
        self.disconnect_events_seen += 1

        client_name = self.extract_client_name(line, 'CLIENT_CLIENT_DISCONNECT')
        if not client_name:
            self.ignored_disconnect_no_client_name += 1
            return

        # Only process if we have a matching connect
        if client_name not in self.connected_clients:
            self.ignored_disconnect_no_matching_connect += 1
            return

        # Count total disconnects
        self.total_disconnects += 1

        # Extract disconnect reason
        reason = self.extract_disconnect_reason(line)

        # Count disconnect reasons
        if reason == 'tcp_reset':
            self.total_tcp_resets += 1
        elif reason == 'tcp_closed':
            self.total_tcp_closed += 1

        # Record this disconnect
        self.last_disconnect[client_name] = (timestamp, reason)

        # Remove from connected clients
        del self.connected_clients[client_name]

    def process_line(self, line: str):
        """Process a single log line."""
        # Check for event types first
        is_connect = 'CLIENT_CLIENT_CONNECT' in line
        is_disconnect = 'CLIENT_CLIENT_DISCONNECT' in line

        if not is_connect and not is_disconnect:
            return

        # Extract timestamp
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2}T[\d:\.]+\+\d{2}:\d{2})', line)
        if not timestamp_match:
            if is_connect:
                self.connect_events_seen += 1
                self.ignored_connect_no_timestamp += 1
            elif is_disconnect:
                self.disconnect_events_seen += 1
                self.ignored_disconnect_no_timestamp += 1
            return

        timestamp = self.parse_timestamp(timestamp_match.group(1))
        if not timestamp:
            if is_connect:
                self.connect_events_seen += 1
                self.ignored_connect_no_timestamp += 1
            elif is_disconnect:
                self.disconnect_events_seen += 1
                self.ignored_disconnect_no_timestamp += 1
            return

        # Track time range
        if self.first_timestamp is None:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp

        # Process based on event type
        if is_connect:
            self.process_connect(timestamp, line)
        elif is_disconnect:
            self.process_disconnect(timestamp, line)

    def generate_report(self) -> str:
        """Generate the analysis report."""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("CLIENT RECONNECTION ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")

        # Time range information
        if self.first_timestamp and self.last_timestamp:
            duration = (self.last_timestamp - self.first_timestamp).total_seconds()
            duration_hours = duration / 3600
            duration_days = duration / 86400

            report_lines.append("Log Analysis Time Range:")
            report_lines.append("-" * 80)
            report_lines.append(f"  First entry processed:                     {self.first_timestamp.isoformat()}")
            report_lines.append(f"  Last entry processed:                      {self.last_timestamp.isoformat()}")
            report_lines.append(f"  Total duration:                            {duration:.2f} seconds ({duration_hours:.2f} hours, {duration_days:.2f} days)")
            report_lines.append("")

        report_lines.append(f"Total Connections:                          {self.total_connections}")
        report_lines.append(f"Total Disconnects:                          {self.total_disconnects}")
        report_lines.append(f"Total 'Peer TCP Reset' Disconnects:         {self.total_tcp_resets}")
        report_lines.append(f"Total 'Peer TCP Closed' Disconnects:        {self.total_tcp_closed}")
        report_lines.append("")
        report_lines.append(f"Total Client Reconnects:                    {self.total_reconnects}")
        report_lines.append(f"Reconnects after 'Peer TCP Reset':          {self.reconnects_after_tcp_reset}")
        report_lines.append(f"Reconnects after 'Peer TCP Closed':         {self.reconnects_after_tcp_closed}")
        report_lines.append("")

        if self.reconnect_times:
            min_time = min(self.reconnect_times)
            max_time = max(self.reconnect_times)
            avg_time = sum(self.reconnect_times) / len(self.reconnect_times)

            report_lines.append("Reconnection Time Statistics:")
            report_lines.append("-" * 80)
            report_lines.append(f"  Minimum time to reconnect:                {min_time:.2f} seconds")
            report_lines.append(f"  Maximum time to reconnect:                {max_time:.2f} seconds")
            report_lines.append(f"  Average time to reconnect:                {avg_time:.2f} seconds")
        else:
            report_lines.append("Reconnection Time Statistics:")
            report_lines.append("-" * 80)
            report_lines.append("  No reconnection timing data available")

        report_lines.append("")
        report_lines.append("Event Processing Statistics:")
        report_lines.append("-" * 80)
        report_lines.append(f"  CONNECT events seen:                       {self.connect_events_seen}")
        report_lines.append(f"  CONNECT events processed:                  {self.total_connections}")
        report_lines.append(f"  CONNECT events ignored (no timestamp):     {self.ignored_connect_no_timestamp}")
        report_lines.append(f"  CONNECT events ignored (no client name):   {self.ignored_connect_no_client_name}")
        report_lines.append("")
        report_lines.append(f"  DISCONNECT events seen:                    {self.disconnect_events_seen}")
        report_lines.append(f"  DISCONNECT events processed:               {self.total_disconnects}")
        report_lines.append(f"  DISCONNECT events ignored (no timestamp):  {self.ignored_disconnect_no_timestamp}")
        report_lines.append(f"  DISCONNECT events ignored (no client name): {self.ignored_disconnect_no_client_name}")
        report_lines.append(f"  DISCONNECT events ignored (no matching connect): {self.ignored_disconnect_no_matching_connect}")

        report_lines.append("")
        report_lines.append("=" * 80)
        return "\n".join(report_lines)


def find_and_sort_log_files(directory: str) -> List[str]:
    """
    Find all event log files in the directory and sort them chronologically.
    Oldest files (highest suffix number) come first.
    """
    dir_path = Path(directory)

    if not dir_path.is_dir():
        raise ValueError(f"'{directory}' is not a valid directory")

    # Find all event.log* files
    log_files = []

    # Pattern for event.log and event.log.N
    for file_path in dir_path.glob('event.log*'):
        if file_path.is_file():
            log_files.append(str(file_path))

    if not log_files:
        raise ValueError(f"No event.log files found in '{directory}'")

    # Sort chronologically: oldest (highest number) to newest
    def sort_key(filepath):
        basename = os.path.basename(filepath)
        if basename == 'event.log':
            # Current log is newest, so give it a sort key of 0
            return 0
        elif '.' in basename:
            # Extract the suffix number
            parts = basename.split('.')
            try:
                # event.log.20 -> return 20 (we will reverse sort on this so higher numbers come first)
                return int(parts[2])
            except (ValueError, IndexError):
                return 0
        return 0

    log_files.sort(key=sort_key, reverse=True)
    return log_files


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_client_reconnects.py <log_directory>", file=sys.stderr)
        sys.exit(1)

    log_directory = sys.argv[1]

    try:
        # Find and sort log files chronologically
        log_files = find_and_sort_log_files(log_directory)

        print(f"Processing {len(log_files)} log file(s) in chronological order:", file=sys.stderr)
        for log_file in log_files:
            print(f"  - {os.path.basename(log_file)}", file=sys.stderr)
        print("", file=sys.stderr)

        tracker = ReconnectionTracker()

        # Process each log file in chronological order
        for log_file in log_files:
            with open(log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        tracker.process_line(line.strip())
                    except Exception as e:
                        print(f"Warning: Error processing {log_file} line {line_num}: {e}", file=sys.stderr)

        # Generate and print report
        print(tracker.generate_report())

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
