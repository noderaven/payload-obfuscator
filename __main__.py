"""CLI shim -- delegates to src/__main__.py."""
import sys
from src.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
