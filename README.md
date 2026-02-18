# Event Log Analyzers

Python scripts for analyzing Solace broker event logs.

## Overview

This repository contains tools for analyzing client connection patterns in Solace message broker event logs.

## Analyzers

### 1. Client Connection Analyzer (`analyze_client_connections.py`)

Analyzes connection metrics per source IP address from a single log file.

**Usage:**
```bash
./analyze_client_connections.py <logfile>
```

**Metrics:**
- Total connections per source IP
- Average connection duration per IP
- Maximum concurrent connections per IP
- TCP reset count per IP

### 2. Client Reconnection Analyzer (`analyze_client_reconnects.py`)

Analyzes client reconnection patterns across rotated log files in a directory.

**Usage:**
```bash
./analyze_client_reconnects.py <log_directory>
```

**Metrics:**
- Total client reconnections
- Reconnections after TCP reset vs. TCP closed
- Min/max/average reconnection time
- Event processing statistics

## Log File Format

The scripts process Solace broker event logs with:
- ISO 8601 timestamps
- CLIENT_CLIENT_CONNECT and CLIENT_CLIENT_DISCONNECT events
- Rotated log files (event.log, event.log.1, event.log.2, etc.)

See `CLAUDE.md` for detailed log format documentation and architecture details.

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## Documentation

- `CLAUDE.md` - Architecture and detailed format specification
- `annotated-event-log.txt` - Example logs with field annotations
