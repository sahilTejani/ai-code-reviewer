#!/usr/bin/env python3
"""Autonomous AI-Powered Code Base Reviewer & Security Auditor with Exhaustive Multi-Model Fallback & Auto-Retry."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
import time
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import types
from google.genai.errors import APIError

# Maximum allowed file size for review (1 MB)
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024

# Enhanced security patterns and ignored directories
BLOCKED_PATTERNS = {".env", "id_rsa", "id_ed25519", "credentials.json", ".pem", ".key", "token.json"}
IGNORED_DIRS = {".git", "__pycache__", "venv", ".venv", "env", ".vscode", "node_modules", "dist", "build", ".tox"}
# Comprehensive supported extensions covering web, programming, configs, markup, and scripts
SUPPORTED_EXTENSIONS = {
    # Web & Frontend
    ".html", ".htm", ".css", ".scss", ".sass", ".less", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    # Backend & Programming Languages
    ".py", ".pyw", ".java", ".cpp", ".cc", ".c", ".h", ".hpp", ".cs", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".kts", ".scala", ".pl",
    # Shell & Scripts
    ".sh", ".bash", ".zsh", ".bat", ".ps1",
    # Data, Config & Markup
    ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg", ".conf", ".sql",
    # Documentation & Text
    ".md", ".txt", ".csv"
}

SYSTEM_INSTRUCTION = (
    "You are an expert Autonomous AI-Powered Code Base Reviewer & Security Auditor.\n"
    "Analyze the provided code strictly for:\n"
    "1. Security vulnerabilities (injection, leaks, insecure configurations)\n"
    "2. Bugs and edge-case logical errors\n"
    "3. Performance optimizations\n"
    "4. Adherence to idiomatic best practices\n"
    "Provide a concise, professional markdown report for this specific file."
)


def is_safe_path(target_path: Path, root_path: Path) -> bool:
    """Ensure the path does not target sensitive environment/credential files and stays within root."""
    if any(blocked in target_path.name.lower() for blocked in BLOCKED_PATTERNS):
        return False
    try:
        target_path.resolve().relative_to(root_path.resolve())
    except ValueError:
        return False
    return True


def audit_file_content(client: genai.Client, file_path: Path, primary_model: str) -> tuple[str, str]:
    """Reads a single file and tries all available Gemini models sequentially until a successful response is received."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code_content = f.read()
    except OSError as e:
        return str(file_path), f"❌ Error reading file: {e}"

    if len(code_content.strip()) == 0:
        return str(file_path), "⚠️ File is empty, skipped."

    user_prompt = f"Analyze the source code of `{file_path.name}` enclosed in the tags:\n\n<source_code>\n{code_content}\n</source_code>"

    # Exhaustive pool of standard Gemini models to ensure maximum availability
    models_to_try = [
        primary_model,
        "gemini-3.8-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-pro"
    ]
    models_to_try = list(dict.fromkeys(models_to_try))  # Remove duplicates

    max_retries_per_model = 2
    backoff_delay = 2

    for model_name in models_to_try:
        for attempt in range(max_retries_per_model):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        temperature=0.2,
                    ),
                )
                return str(file_path), f"*(Successfully audited via model: `{model_name}`)*\n\n{response.text}"
            except APIError as e:
                error_msg = getattr(e, 'message', str(e))
                # If high demand or rate limit, retry same model briefly
                if any(keyword in error_msg.lower() for keyword in ["high demand", "resource exhausted", "429", "too many requests"]):
                    if attempt < max_retries_per_model - 1:
                        time.sleep(backoff_delay)
                        continue
                # If model is deprecated or not found, immediately move to the next model in the list
                if any(keyword in error_msg.lower() for keyword in ["no longer available", "not found", "404"]):
                    break
                # For other errors, break inner loop to try next model
                break
            except Exception:
                break

    return str(file_path), "❌ Gemini API Error: All available models (3.8-flash, 2.0-flash, 1.5-flash, 1.5-pro) failed or are currently busy."


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Autonomous AI-Powered Security Auditor with Exhaustive Multi-Model Fallback."
    )
    parser.add_argument("path", help="Path to a source file or a directory to review")
    parser.add_argument(
        "--model",
        default="gemini-3.8-flash",
        help="Gemini model ID to start with (default: gemini-3.8-flash)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent files to audit (default: 4)",
    )
    parser.add_argument(
        "--output",
        default="security_report.md",
        help="Path to save the generated master markdown report (default: security_report.md)",
    )

    args = parser.parse_args()
    target_path = Path(args.path).resolve()

    if not target_path.exists():
        print(f"❌ Error: Path '{args.path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print(f"❌ Error: 'GEMINI_API_KEY' environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    files_to_audit = []
    root_dir = target_path if target_path.is_dir() else target_path.parent

    if target_path.is_file():
        if not is_safe_path(target_path, root_dir):
            print(f"❌ Security Warning: Auditing sensitive file '{target_path.name}' is prohibited.", file=sys.stderr)
            sys.exit(1)
        try:
            if 0 < target_path.stat().st_size <= MAX_FILE_SIZE_BYTES:
                files_to_audit.append(target_path)
        except OSError:
            print(f"❌ Error accessing file stats for {target_path.name}", file=sys.stderr)
            sys.exit(1)
    elif target_path.is_dir():
        print(f"📂 Scanning directory: {target_path} ...")
        for root, dirs, files in os.walk(target_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for file in files:
                file_p = Path(root) / file
                if not file_p.is_symlink() and file_p.suffix in SUPPORTED_EXTENSIONS and is_safe_path(file_p, target_path):
                    try:
                        if 0 < file_p.stat().st_size <= MAX_FILE_SIZE_BYTES:
                            files_to_audit.append(file_p)
                    except OSError:
                        continue

    if not files_to_audit:
        print("⚠️ No valid files found to audit.")
        sys.exit(0)

    files_to_audit = sorted(files_to_audit)

    print(f"🚀 Total files targeted for audit: {len(files_to_audit)}")
    print(f"⚡ Running audits concurrently with {args.workers} workers (trying all available fallback models if needed)...\n")

    master_report_lines = [
        "# Autonomous AI Code Base Review & Security Audit Master Report\n",
        f"**Target Path:** `{target_path}`\n",
        f"**Fallback Model Chain:** `[User Choice, 3.8-flash, 2.0-flash, 1.5-flash, 1.5-pro]`\n",
        f"**Total Files Audited:** `{len(files_to_audit)}`\n",
        "---\n"
    ]

    results_map = {}

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_file = {
            executor.submit(audit_file_content, client, fp, args.model): fp 
            for fp in files_to_audit
        }

        for future in as_completed(future_to_file):
            f_path, report = future.result()
            results_map[f_path] = report

    for idx, fp in enumerate(files_to_audit, 1):
        f_path_str = str(fp)
        report = results_map.get(f_path_str, "❌ Report missing.")
        rel_name = fp.relative_to(target_path) if target_path.is_dir() else fp.name

        print(f"[{idx}/{len(files_to_audit)}] Audit Report for: {rel_name}")
        print("=" * 60)
        print(report)
        print("=" * 60 + "\n")

        master_report_lines.append(f"## File: `{rel_name}`\n")
        master_report_lines.append(report)
        master_report_lines.append("\n\n---\n")

    output_path = Path(args.output)
    try:
        output_path.write_text("\n".join(master_report_lines), encoding="utf-8")
        print(f"✨ Master security report successfully saved to: **{output_path.resolve()}**")
    except OSError as e:
        print(f"❌ Error saving report file: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()