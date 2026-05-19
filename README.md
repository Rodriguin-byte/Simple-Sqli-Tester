# Specialized SQL Injection Testing Tool

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Uma ferramenta especializada e automatizada escrita em Python para identificar vulnerabilidades de **SQL Injection (SQLi)** em aplicações web. O script analisa automaticamente os parâmetros de URLs e formulários HTML, testando-os contra diversas técnicas de injeção.

> [!WARNING]
> **AVISO LEGAL:** Esta ferramenta foi desenvolvida estritamente para fins educacionais e testes de penetração autorizados (Ethical Hacking). O uso deste script contra alvos sem consentimento prévio e por escrito é ilegal.

---

## 🚀 Funcionalidades

* **Deteção Automática de Parâmetros:** Analisa URLs à procura de parâmetros (`?param=val`) e faz *parsing* de formulários HTML (usando BeautifulSoup) para extrair campos de input e textarea.
* **Múltiplos Vetores de Teste:**
    * **Error-Based SQLi:** Deteta falhas através da análise de mensagens de erro específicas de Base de Dados (MySQL, MSSQL, PostgreSQL, Oracle, SQLite).
    * **Time-Based Blind SQLi:** Mede o tempo de resposta do servidor utilizando funções como `SLEEP()` e `WAITFOR DELAY` para confirmar a vulnerabilidade.
    * **Union-Based & Boolean Blind:** Dicionário estruturado de payloads pronto para expansão.
* **Suporte a Sessões Autenticadas:** Permite injetar cookies de sessão para testar páginas atrás de áreas de login.
* **Geração de Relatório:** Cria automaticamente um relatório detalhado em texto limpo (`.txt`) com os resultados, payloads bem-sucedidos e evidências encontradas.
* **Interface Amigável:** Outputs organizados e coloridos no terminal para facilitar a leitura.

---

## 🛠️ Pré-requisitos & Instalação

Antes de executar a ferramenta, garante que tens o Python 3 instalado e as dependências necessárias.

1. Clone o repositório ou descarregue o script.
2. Instale as bibliotecas necessárias correndo o seguinte comando no terminal:

```bash
pip install requests beautifulsoup4 colorama
