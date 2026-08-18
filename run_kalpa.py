#!/usr/bin/env python3
"""
KALPA: Causal Cyber Reasoning System for AI Kavach
Single-Command Autonomous Execution Entrypoint.
"""

import sys
import os

# Ensure package root is in sys.path when executed directly as script
pkg_dir = os.path.dirname(os.path.abspath(__file__))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

from kalpa.cli import main

if __name__ == "__main__":
    main()
