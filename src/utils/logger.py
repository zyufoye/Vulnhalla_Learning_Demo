#!/usr/bin/env python3
"""
Centralized logging configuration for Vulnhalla.

Provides consistent logging setup across all modules with support for:
- Console output (INFO level by default)
- Optional file logging (DEBUG level)
- Environment variable configuration
- Structured logging (JSON) option
"""

import logging
import sys
import os
from pathlib import Path
from typing import Optional