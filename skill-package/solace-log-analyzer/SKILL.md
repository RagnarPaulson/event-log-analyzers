---
name: solace-log-analyzer
description: Generate custom Python scripts to analyze Solace broker event logs. Use when the user asks questions about Solace event logs or requests analysis of CLIENT_CLIENT_CONNECT and CLIENT_CLIENT_DISCONNECT events. Triggers include requests to analyze connection patterns, reconnection behavior, disconnect reasons, client metrics, IP-based statistics, or any custom query about Solace broker logs. Also triggers when the user wants to understand log format specifications or needs help parsing Solace event log files.
---

# Solace Log Analyzer

Generate custom Python scripts to analyze Solace broker event logs based on user questions.

## Quick Start

When the user asks a question about Solace logs:

1. **Read the log format specification**: `references/log-formats.md`
2. **Check parsing patterns**: `references/parsing-patterns.md` for regex examples
3. **Review analysis patterns**: `references/analysis-patterns.md` for common workflows
4. **Reference implementations**: `scripts/` contains working examples
5. **Generate custom script**: Create a Python script that answers the user's specific question

## Common Questions and Approaches

**"Which IPs have the most connections?"**
- Read `log-formats.md` for CONNECT event structure
- Use aggregation pattern from `analysis-patterns.md`
- Extract IP from `from` field, count occurrences

**"Show reconnection patterns for client X"**
- Read `log-formats.md` for both CONNECT and DISCONNECT events
- Use reconnection detection pattern from `analysis-patterns.md`
- Track by client name, detect connects after disconnects
- Reference `scripts/analyze_client_reconnects.py` for implementation

**"Find clients with high TCP reset rates"**
- Read `log-formats.md` for DISCONNECT event structure
- Use filtering and categorization pattern from `analysis-patterns.md`
- Parse disconnect reason, categorize, calculate rates per client

**"Calculate average session duration by VPN"**
- Read `log-formats.md` for event matching strategy
- Use state tracking pattern from `analysis-patterns.md`
- Match CONNECT/DISCONNECT by endpoint, group by VPN, calculate durations

## Reference Material

### Log Format Specifications

Read `references/log-formats.md` for:
- CLIENT_CLIENT_CONNECT event fields and structure
- CLIENT_CLIENT_DISCONNECT event fields and statistics
- Event matching strategy (how to correlate connect/disconnect pairs)
- Log file rotation scheme

**Key matching field**: `<client-ip>:<client-port>` endpoint
- CONNECT: Extract from `from <ip>:<port>`
- DISCONNECT: Extract from third field of `conn(..., ..., <ip>:<port>, ...)`

### Parsing Patterns

Read `references/parsing-patterns.md` for:
- Regex patterns for extracting fields
- Timestamp parsing
- Handling rotated log files
- Error handling strategies

### Analysis Patterns

Read `references/analysis-patterns.md` for:
- Aggregate by field (count/sum grouped by VPN, IP, platform, etc.)
- Track state over time (active connections, lifecycle management)
- Calculate durations and rates
- Filter and categorize (group by disconnect reason, etc.)
- Detect reconnections
- Sample concurrent connections
- Generate formatted reports

## Reference Implementations

Two working examples in `scripts/`:

**`scripts/analyze_client_connections.py`**
- Analyzes connection metrics per source IP
- Demonstrates: endpoint matching, duration calculation, concurrent connection tracking
- Key pattern: Uses `ip:port` for matching but aggregates by IP for reporting

**`scripts/analyze_client_reconnects.py`**
- Analyzes client reconnection patterns across rotated logs
- Demonstrates: client lifecycle tracking, disconnect reason categorization, reconnection detection
- Key pattern: Tracks by client name (not IP) to detect reconnections across different IPs

Use these as architectural examples when generating custom analyzers.

## Example Log Files

`assets/annotated-event-log.txt` contains example Solace event log entries with field annotations.

## Guidelines for Generated Scripts

When generating custom analyzers:

1. **Use standard library only** - No external dependencies (datetime, re, sys, collections)
2. **Make executable** - Include `#!/usr/bin/env python3` shebang
3. **Handle edge cases** - Malformed lines, missing fields, orphaned events
4. **Provide clear output** - Formatted reports with context and statistics
5. **Sort chronologically** - When processing multiple log files
6. **Document assumptions** - What events are being matched, what's being ignored

## Typical Workflow

1. User asks a specific question about Solace logs
2. Read `references/log-formats.md` to understand relevant event structures
3. Consult `references/parsing-patterns.md` for extraction regex
4. Choose appropriate pattern from `references/analysis-patterns.md`
5. Reference implementation scripts for architectural guidance
6. Generate Python script that:
   - Parses the specific fields needed
   - Applies the appropriate analysis pattern
   - Produces formatted output answering the question
7. Test the script with example logs if available

## Log Format Summary

For quick reference without reading full specifications:

**CONNECT events**: Client endpoint (`from ip:port`), VPN, client name, version, platform, auth scheme
**DISCONNECT events**: Endpoint (`conn(..., ..., ip:port, ...)`), reason, 22-field dataplane statistics, connection state

**Event correlation**: Match CONNECT and DISCONNECT by `ip:port` endpoint

**Log rotation**: Process chronologically from oldest (highest suffix) to newest
