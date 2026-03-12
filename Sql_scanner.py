XSS VULNERABILITY SCANNER (TEST VERSION)
Version: 1.0
Language: Python 3.6+
Author: Cybersecurity Student

LEGAL DISCLAIMER
THIS TOOL IS FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTING ONLY.
Unauthorized use of this tool against systems without explicit permission is illegal. The user is solely responsible for any damage or legal repercussions resulting from the use of this script.

SETUP - PREREQUISITES
To run this script, you must have the following installed on your system:

Python 3.6 or higher.

The 'pip' package manager.

SETUP - INSTALLATION
Before running the scanner, you need to install the required Python libraries. Open your terminal or command prompt and run:

Bash
pip install requests beautifulsoup4 urllib3
SETUP - EXECUTION (USAGE)
To use the scanner, provide the target URL as a command-line argument.

Syntax:

Bash
python xss_scanner.py <TARGET_URL>
Example:

Bash
python xss_scanner.py http://example.com
HOW IT WORKS
Connectivity Test: The script first attempts to establish a connection with the target to ensure it is reachable.

Form Discovery: It parses the HTML content using BeautifulSoup to identify all <form> elements, their methods (GET/POST), and input fields.

Payload Injection: It appends a basic XSS payload (<script>alert('XSS')</script>) to a test parameter in the URL.

Reflection Check: It analyzes the server's response. If the exact payload string is found in the HTML source code, the script flags a potential vulnerability.

LIMITATIONS
Simple Reflection: This version only tests for reflected XSS via the URL (GET method).

No Automated Form Submission: It discovers forms but does not automatically submit payloads into every input field.

WAF/Sanitization: Many modern web applications use Web Application Firewalls (WAF) or sanitization libraries that may block or encode this simple payload.

Manual Verification: Findings should always be manually verified to confirm if the script is actually executed by a browser.

OUTPUT
The script provides real-time feedback in the terminal, including:

Connection status and HTTP codes.

Detailed list of found forms and input types.

Success or failure of the XSS reflection test.
