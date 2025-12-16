#!/usr/bin/env python3
"""
Application Configuration Module

Loads general application configuration from .env file or environment variables.
Handles CodeQL path, GitHub token, and other non-LLM settings.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load .env file if it exists, otherwise try .env.example
if os.path.exists(".env"):
    load_dotenv(".env")
elif os.path.exists(".env.example"):
    load_dotenv(".env.example")


def get_codeql_path() -> str:
    """
    Get CodeQL executable path from .env file or environment variables.
    
    Returns:
        Path to CodeQL executable. Defaults to "codeql" if not set.
    """
    path = os.getenv("CODEQL_PATH", "codeql")
    # Strip quotes and Python raw string prefix if present
    if path and path != "codeql":
        path = path.strip('"').strip("'")
        # Remove 'r' prefix if present (Python raw string syntax, not valid in .env)
        if path.startswith("r\"") or path.startswith("r'"):
            path = path[2:]
            path = path.strip('"').strip("'")
    return path


def get_github_token() -> Optional[str]:
    """
    Get GitHub API token from .env file or environment variables.
    
    Returns:
        GitHub token string if set, None otherwise.
    """
    return os.getenv("GITHUB_TOKEN")

