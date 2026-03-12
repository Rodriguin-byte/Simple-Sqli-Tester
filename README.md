#  Simple Sqli Tester

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)](CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/seu-usuario/sql-injection-tester/graphs/commit-activity)

Uma ferramenta especializada em testar vulnerabilidades de SQL Injection, desenvolvida para fins educacionais e testes de penetração autorizados.

##  Sobre o Projeto

O SQL Injection Tester é uma ferramenta focada exclusivamente na deteção e exploração de vulnerabilidades de injeção SQL. Inspirada em ferramentas profissionais como sqlmap, esta ferramenta foi desenvolvida para ser **educacional, precisa e fácil de usar**, permitindo compreender profundamente como diferentes tipos de SQL Injection funcionam.

###  Funcionalidades Principais

| Tipo | Descrição | Características |
|------|-----------|-----------------|
|  **Error-Based** | Deteção baseada em mensagens de erro da base de dados | Suporte para MySQL, MSSQL, PostgreSQL, Oracle, SQLite |
|  **Time-Based Blind** | Injeção cega baseada em delays | Testes com SLEEP(), WAITFOR DELAY, pg_sleep() |
|  **Union-Based** | Extração de dados usando UNION | Descoberta de colunas, extração de versão e tabelas |
|  **Boolean-Based Blind** | Injeção cega baseada em verdadeiro/falso | Testes condicionais com AND/OR |

###  Bases de Dados Suportadas

| Database | Error Patterns | Time Functions | Union Support |
|----------|---------------|----------------|---------------|
| MySQL | ✓ SQL syntax, mysql_fetch | ✓ SLEEP() | ✓ Completo |
| MSSQL | ✓ Unclosed quotation, OLE DB | ✓ WAITFOR DELAY | ✓ Completo |
| PostgreSQL | ✓ PostgreSQL ERROR, pg_* | ✓ pg_sleep() | ✓ Completo |
| Oracle | ✓ ORA-* | ✓ DBMS_LOCK.SLEEP | ✓ Completo |
| SQLite | ✓ SQLite error | ✗ | ✓ Básico |

##  Instalação

### Pré-requisitos

- Python 3.6 ou superior
- pip (gerenciador de pacotes Python)

### Passos de Instalação

1. **Clone o repositório**
```bash
git clone https://github.com/seu-usuario/sql-injection-tester.git
cd sql-injection-tester
