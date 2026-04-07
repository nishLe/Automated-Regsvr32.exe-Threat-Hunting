# Regsvr32 Threat Hunting Exporter

This tool queries Elasticsearch for suspicious regsvr32 activity on Windows and exports results to an Excel workbook with a general sheet plus per-rule query and validation sheets.

## Features

- Queries regsvr32 start events on Windows hosts.
- Applies 11 detection rules with short descriptions.
- Generates a multi-sheet XLSX report with optional query-only or validation-only output.
- Supports dry-run to print Elasticsearch query bodies.
- Supports query validation using the Elasticsearch validate API.

## Requirements

- Python 3.9+
- Elasticsearch cluster with Windows endpoint telemetry indexed

Python packages:

- python-dotenv
- elasticsearch
- openpyxl

## Setup

1) Create a .env file next to the script:

```
ES_URL=https://your-elasticsearch:9200
ES_API_KEY=your_api_key
ES_INDEX=your-index-pattern-*
VERIFY_CERTS=false
```

2) Install dependencies:

```
pip install python-dotenv elasticsearch openpyxl
```

## Usage

```
python regsvr32_hunter.py import <time>
```

Time format examples:

- Seconds: 10s, 30s
- Minutes: 5m, 30m
- Hours: 1h, 6h, 12h, 24h
- Days: 2d, 7d, 30d
- Months: 1mo, 3mo, 6mo
- Years: 1y, 2y
- All time: all

Optional flags:

- --dry-run       Print query bodies and exit
- --validate      Validate queries using Elasticsearch validate API
- --query-only    Export only 1st Query sheets (skip Validation sheets)
- --validation-only  Export only Validation sheets (skip 1st Query sheets)

Examples:

```
python regsvr32_hunter.py import 24h
python regsvr32_hunter.py import 7d --query-only
python regsvr32_hunter.py import all --validation-only
python regsvr32_hunter.py import 1mo --dry-run
```

## Output

The tool writes an XLSX file to the current directory:

- General_All_Regsvr32
- Per_Rule_Detections (aggregated classification across rules)
- Rule 1 .. Rule 11 sheets with both query and validation views

Output filename format:

```
regsvr32_perrulerule_<time_label>_<utc_timestamp>.xlsx
```

## Notes

- The script requires ES_URL and ES_API_KEY. It will exit if missing.
- VERIFY_CERTS is optional; set to true to validate TLS certificates.
- Sheet names are truncated to 31 characters due to Excel limits.

## Rule Coverage (1-11)

1) Scriptlet/Remote execution (/i: + scrobj.dll/URL/UNC/.sct)
2) Non-system path DLL
3) Non-standard extension
4) Double-extension masquerade
5) Network activity/connections
6) Suspicious parent process
7) Unsigned DLL
8) Child processes spawned by regsvr32
9) regsvr32 unsigned or untrusted signature
10) SMB share remote execution
11) Renamed regsvr32

## Troubleshooting

- Use --dry-run to confirm the queries.
- Use --validate to identify invalid query bodies or mapping issues.
- Ensure your index contains fields like process.name, process.command_line, and event.type.
