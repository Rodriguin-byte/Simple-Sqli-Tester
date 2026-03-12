

#  Specialized SQL Injection Testing Tool

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)](CONTRIBUTING.md)

A specialized tool for testing SQL Injection vulnerabilities, developed for educational purposes and authorized penetration testing.

##  About The Project

The SQL Injection Tester is a tool focused exclusively on detecting and exploiting SQL injection vulnerabilities. Inspired by professional tools like sqlmap, this tool was developed to be **educational, precise, and easy to use**, allowing deep understanding of how different types of SQL Injection work.

###  Main Features

| Type | Description | Support |
|------|-------------|---------|
|  **Error-Based** | Detection based on database error messages | MySQL, MSSQL, PostgreSQL, Oracle, SQLite |
|  **Time-Based Blind** | Blind injection based on delays | SLEEP(), WAITFOR DELAY, pg_sleep() |
|  **Union-Based** | Data extraction using UNION | Column discovery, version and table extraction |
|  **Boolean-Based Blind** | Blind injection based on true/false | Conditional tests with AND/OR |

###  Supported Databases

| Database | Error Patterns | Time Functions | Union Support |
|----------|---------------|----------------|---------------|
| MySQL | ✓ SQL syntax, mysql_fetch | ✓ SLEEP() | ✓ Full |
| MSSQL | ✓ Unclosed quotation, OLE DB | ✓ WAITFOR DELAY | ✓ Full |
| PostgreSQL | ✓ PostgreSQL ERROR, pg_* | ✓ pg_sleep() | ✓ Full |
| Oracle | ✓ ORA-* | ✓ DBMS_LOCK.SLEEP | ✓ Full |
| SQLite | ✓ SQLite error | ✗ | ✓ Basic |

##  Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Installation Steps

1. **Clone the repository**
```bash
git clone https://github.com/your-username/sql-injection-tester.git
cd sql-injection-tester
