# AI-Powered Code Ethics Auditor (Multilanguage MVP)

Scan code for **ethical, privacy, bias, and security risks** across multiple languages and generate a **plain-language AI summary** plus a **downloadable PDF report**.

**Supported languages:** Python · JavaScript · Java · C · C++

> This project combines **rule-based static analysis** (regex + AST) with an **LLM** to explain *why issues matter* and how to **fix them quickly**.

# Features

- **Language picker** with Python (AST + regex), JavaScript/Java/C/C++ (Tree-sitter AST + regex).
- **Actionable findings**: severity (High/Medium/Low), line numbers, code snippet (“evidence”), and remediation advice.
- **AI Ethical Summary**: executive summary, top risks, and quick fixes in plain language (OpenAI).
- **PDF export**: one-click, shareable **Ethics Audit Report**.
- **Graceful fallback**: if Tree-sitter isn’t installed, non-Python languages run regex-only checks.

# What it Detects (high level)

- **Secrets & credentials**: hardcoded keys/tokens/passwords
- **Privacy/PII hints**: email/phone patterns in code samples
- **Bias indicators**: sensitive attributes (gender, race, religion, etc.)
- **SQL injection patterns** (concatenated queries, f-strings)
- **Weak crypto**: MD5/SHA-1, non-crypto RNG for tokens
- **Dynamic/unsafe code**: `eval`/`exec`, JS `new Function`
- **OS command risks**: `subprocess(shell=True)`, `system()`, `Runtime.exec()`
- **Insecure parsing/deserialization**: `pickle`, `yaml.load` without SafeLoader
- **Broad exception handling** (Python)
- **ML practice**: `train_test_split` without `stratify` (Python)
- **Format-string risks** (C/C++ `printf`-style heuristics)
- **Plain HTTP** endpoints

> These rules are **heuristics**; some false positives/negatives are expected.

---

# Architecture

1. **Upload Code** (or paste)  
2. **Static Analysis**  
   - Regex checks for quick wins (all languages)  
   - AST checks:  
     - Python: built-in `ast`  
     - JS/Java/C/C++: **Tree-sitter** via `tree_sitter_languages`  
3. **AI Ethical Summary** (OpenAI)  
4. **PDF Report** (ReportLab)

---

# Installation

# Prerequisites
- Python 3.9+ recommended
- (Optional for deeper JS/Java/C/C++ checks) **Tree-sitter** bindings

# Install
```bash
git clone <your-repo-url>
cd <your-repo-folder>
pip install -r requirements.txt
