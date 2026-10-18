# AI Code Reviewer & Security Auditor

An autonomous AI-powered CLI tool designed to scan local directories or individual files, check for security vulnerabilities, logic bugs, and best practices using Google Gemini models, and generate a comprehensive markdown report.

## Features
- **Recursive Directory Scanning:** Scans target folders while ignoring system and secret directories.
- **Concurrent Processing:** Uses multithreading (`ThreadPoolExecutor`) for fast execution.
- **Multi-Model Fallback Chain:** Automatically switches to alternative Gemini models if the primary model is busy or unavailable.
- **Auto-Retry Mechanism:** Handles rate limits and high demand errors gracefully.
- **Automated Markdown Export:** Saves a deterministic, alphabetically sorted master report (`security_report.md`).

## Installation & Setup

1. Clone or download this repository.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt