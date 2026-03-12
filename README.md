# SQL Injection Scanner TOOL
Version: 1.0

Language: Python 3.6+

Features: Error-based, Time-based, and Union-based detection

# LEGAL DISCLAIMER
THIS TOOL IS FOR EDUCATIONAL PURPOSES AND AUTHORIZED PENETRATION TESTING ONLY.

Testing targets without explicit written consent is illegal and may lead to criminal charges. The developer assumes no liability for misuse or damage caused by this program.

# SETUP - PREREQUISITES
To ensure the script functions correctly, you must have:

Python 3.6 or higher installed.

An active internet connection (to reach targets).

Terminal support for ANSI colors (standard in Linux/macOS; Windows may require modern Terminal).

# SETUP - INSTALLATION
The script relies on several external libraries for HTTP handling, HTML parsing, and terminal coloring. Install the requirements using the following command:


pip install requests beautifulsoup4 colorama urllib3
SETUP - EXECUTION (USAGE)
The tool uses a Command Line Interface (CLI). You can pass the target URL and optional parameters directly through the terminal.

Basic Usage:

python sql_tester.py http://example.com/page.php?id=1
Advanced Usage (with session cookies and delay):

python sql_tester.py http://example.com/target --cookie "PHPSESSID=12345" --delay 2
Arguments:

url: The target address to scan.

--cookie: (Optional) Provide a session cookie for testing pages behind a login.

--delay: (Optional) Set the time in seconds between requests to avoid triggering security blocks. Default is 1 second.

--timeout: (Optional) Set the maximum wait time for server responses.

# CORE FUNCTIONALITIES
Parameter Auto-Detection: The script automatically extracts parameters from the URL query string and scans HTML forms (<input> and <textarea>) for potential injection points.

Error-Based Detection: Scans for specific database error signatures (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) triggered by malicious payloads.

Time-Based Blind SQLi: Measures server response latency to detect if "SLEEP" or "WAITFOR" commands are being executed by the database.

Union-Based Testing: Attempts to determine the number of columns and extract database metadata.

Automated Reporting: Generates a detailed text file report (sql_injection_report_[timestamp].txt) containing all vulnerable parameters, payloads used, and evidence found.

# LIMITATIONS
False Positives: High server load can mimic Time-Based injection. Manual verification is recommended.

Sanitization: The tool may not bypass sophisticated Web Application Firewalls (WAF) or modern prepared statements.

Database Extraction: The version-gathering and table-extraction features are modular and may require manual payload adjustment depending on the database environment.

# OUTPUT DATA
The tool provides color-coded terminal output:

Blue [*]: Informational messages and detection progress.

Green [+]: Successful discovery of parameters or saved reports.

Red [!]: Confirmed vulnerability detection.

Yellow [-]: Errors or connectivity issues
