"""Allows `python -m app` from the project root."""

import sys

from app.main import main

if __name__ == "__main__":
    sys.exit(main())
