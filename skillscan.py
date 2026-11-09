#!/usr/bin/env python3
"""Shim so `python3 skillscan.py <folder>` works as well as
`python3 -m skillscan <folder>`."""

import sys

from skillscan.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
