#!/usr/bin/env python3

"""
Command-line entry point for the payload obfuscator.
"""

import sys
from .src.obfuscator import main

if __name__ == "__main__":
    sys.exit(main()) 