# Solace Event Log Analysis - Claude Context Repository

This repository provides **context and log format specifications** for Claude to generate custom Python scripts that analyze Solace broker event logs.

## Purpose

Rather than providing pre-built analysis tools, this repository serves as a **knowledge base** that enables Claude Code to:
- Understand Solace event log formats
- Generate custom analyzers for specific questions
- Provide working examples as reference implementations

## How to Use This Repository

1. **Ask Claude specific questions about your logs**:
   - "Which client IPs have the most TCP resets?"
   - "Show me reconnection patterns for client X"
   - "Find all clients using TLS version 1.1"
   - "Calculate average session duration by VPN"

2. **Claude will generate custom Python scripts** using the log format specifications in `CLAUDE.md`

3. **Example scripts are included** as reference implementations:
   - `analyze_client_connections.py` - Connection metrics per source IP
   - `analyze_client_reconnects.py` - Reconnection pattern analysis

## Extending This Repository

To enhance Claude's ability to generate analyzers, **add more log format specifications** to `CLAUDE.md`:

### Currently Documented Formats:
- ✅ Solace broker event logs (CLIENT_CLIENT_CONNECT, CLIENT_CLIENT_DISCONNECT)

### Add New Formats By Documenting:
- **Other Solace event types**: QUEUE events, BRIDGE events, VPN events, etc.
- **Message logs**: Individual message tracking, publish/subscribe patterns
- **System logs**: Broker health, memory usage, queue statistics
- **Audit logs**: Administrative actions, configuration changes
- **Performance metrics**: Dataplane statistics, ingress/egress rates

### How to Add a New Log Format:

1. Add a new section to `CLAUDE.md` with:
   - Event type name and purpose
   - Complete line format with field descriptions
   - Example log lines (annotated)
   - Key fields for matching/correlating events
   - Common analysis patterns

2. Include annotated examples in separate `.txt` files

3. Optionally provide a reference implementation script

## Log Format Documentation

See `CLAUDE.md` for:
- Detailed event log structure
- Field-by-field specifications
- Event matching strategies
- Example analysis patterns
- Architecture of reference implementations

## Requirements

Generated scripts use:
- Python 3.6+
- Standard library only (no external dependencies)
- Executable with `#!/usr/bin/env python3`

## Files in This Repository

- **`CLAUDE.md`** - Primary context file with log format specifications
- **`README.md`** - This file
- **`annotated-event-log.txt`** - Example event logs with field annotations
- **`analyze_client_connections.py`** - Reference: IP-based connection analysis
- **`analyze_client_reconnects.py`** - Reference: Client reconnection patterns

## Examples of Questions You Can Ask

- "Generate a script to find all clients that had more than 10 reconnections"
- "Show me clients with average connection duration under 5 seconds"
- "Which VPNs have the highest disconnect rate?"
- "Find clients using deprecated TLS versions"
- "Correlate disconnect reasons with client platform types"

Each question will result in a custom Python script tailored to your specific analysis needs.
