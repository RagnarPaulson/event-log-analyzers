#!/usr/bin/env python3
"""
Log file analyzer for CLIENT_CLIENT_CONNECT and CLIENT_CLIENT_DISCONNECT events.
Tracks connection metrics per source IP address.
"""

import re
import sys
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional


class ConnectionTracker:
    def __init__(self):
        # Active connections: key = "ip:port", value = (ip, connect_timestamp)
        self.active_connections: Dict[str, Tuple[str, datetime]] = {}
        
        # Per-IP statistics
        self.ip_stats = defaultdict(lambda: {
            'total_connections': 0,
            'connection_durations': [],
            'tcp_resets': 0,
            'concurrent_connections_samples': []
        })
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse ISO 8601 timestamp."""
        try:
            return datetime.fromisoformat(timestamp_str.replace('+00:00', '+00:00'))
        except Exception as e:
            print(f"Warning: Failed to parse timestamp '{timestamp_str}': {e}", file=sys.stderr)
            return None
    
    def extract_ip_from_endpoint(self, endpoint: str) -> str:
        """Extract IP address from 'ip:port' string."""
        return endpoint.rsplit(':', 1)[0]
    
    def process_connect(self, timestamp: datetime, line: str):
        """Process CLIENT_CLIENT_CONNECT entry."""
        # Pattern: from <ip:port>
        match = re.search(r'from\s+([\d\.]+:\d+)', line)
        if not match:
            return
        
        endpoint = match.group(1)
        ip = self.extract_ip_from_endpoint(endpoint)
        
        # Store active connection
        self.active_connections[endpoint] = (ip, timestamp)
        
        # Update statistics
        self.ip_stats[ip]['total_connections'] += 1
        
        # Sample concurrent connections for this IP
        concurrent = sum(1 for ep, (ip_addr, _) in self.active_connections.items() if ip_addr == ip)
        self.ip_stats[ip]['concurrent_connections_samples'].append(concurrent)
    
    def process_disconnect(self, timestamp: datetime, line: str):
        """Process CLIENT_CLIENT_DISCONNECT entry."""
        # Pattern: conn(..., <ip:port>, ...)
        match = re.search(r'conn\([^,]+,\s*[^,]+,\s*([\d\.]+:\d+)', line)
        if not match:
            return
        
        endpoint = match.group(1)
        
        # Check if we have a matching connect
        if endpoint not in self.active_connections:
            return
        
        ip, connect_time = self.active_connections[endpoint]
        
        # Calculate duration
        duration = (timestamp - connect_time).total_seconds()
        self.ip_stats[ip]['connection_durations'].append(duration)
        
        # Check for TCP reset
        if 'Peer TCP Reset' in line:
            self.ip_stats[ip]['tcp_resets'] += 1
        
        # Sample concurrent connections before removing
        concurrent = sum(1 for ep, (ip_addr, _) in self.active_connections.items() if ip_addr == ip)
        self.ip_stats[ip]['concurrent_connections_samples'].append(concurrent)
        
        # Remove from active connections
        del self.active_connections[endpoint]
    
    def process_line(self, line: str):
        """Process a single log line."""
        # Extract timestamp
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2}T[\d:\.]+\+\d{2}:\d{2})', line)
        if not timestamp_match:
            return
        
        timestamp = self.parse_timestamp(timestamp_match.group(1))
        if not timestamp:
            return
        
        # Process based on event type
        if 'CLIENT_CLIENT_CONNECT' in line:
            self.process_connect(timestamp, line)
        elif 'CLIENT_CLIENT_DISCONNECT' in line:
            self.process_disconnect(timestamp, line)
    
    def generate_report(self) -> str:
        """Generate the analysis report."""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("CLIENT CONNECTION ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")
        report_lines.append(f"Total unique source IP addresses: {len(self.ip_stats)}")
        report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Sort IPs by total connections (descending)
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]['total_connections'],
            reverse=True
        )
        
        for ip, stats in sorted_ips:
            report_lines.append(f"Source IP: {ip}")
            report_lines.append("-" * 80)
            report_lines.append(f"  Total Connections:           {stats['total_connections']}")
            
            if stats['connection_durations']:
                avg_duration = sum(stats['connection_durations']) / len(stats['connection_durations'])
                report_lines.append(f"  Average Connection Duration: {avg_duration:.2f} seconds")
            else:
                report_lines.append(f"  Average Connection Duration: N/A (no completed connections)")
            
            if stats['concurrent_connections_samples']:
                max_concurrent = max(stats['concurrent_connections_samples'])
                report_lines.append(f"  Max Concurrent Connections:  {max_concurrent}")
            else:
                report_lines.append(f"  Max Concurrent Connections:  0")
            
            report_lines.append(f"  TCP Resets (Peer):           {stats['tcp_resets']}")
            report_lines.append("")
        
        report_lines.append("=" * 80)
        return "\n".join(report_lines)


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_client_connections.py <logfile>", file=sys.stderr)
        sys.exit(1)
    
    logfile = sys.argv[1]
    
    tracker = ConnectionTracker()
    
    try:
        with open(logfile, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    tracker.process_line(line.strip())
                except Exception as e:
                    print(f"Warning: Error processing line {line_num}: {e}", file=sys.stderr)
        
        # Generate and print report
        print(tracker.generate_report())
        
    except FileNotFoundError:
        print(f"Error: File '{logfile}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
