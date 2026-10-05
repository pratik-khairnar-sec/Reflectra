"""
Reflectra __main__ entrypoint.
Allows running Reflectra via `python -m reflectra`.
"""

import sys
from reflectra.cli import main

if __name__ == "__main__":
    sys.exit(main())
