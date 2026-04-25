#!/usr/bin/env python3
"""Root launcher — delegates to the phishing-analyzer skill.

Usage:
    python main.py suspicious.eml
    python main.py suspicious.eml --json
"""

import os
import sys

# Add the skill's scripts/ directory to the path so imports resolve correctly.
_SKILL_SCRIPTS = os.path.join(
    os.path.dirname(__file__),
    ".claude", "skills", "phishing-analyzer", "scripts",
)
sys.path.insert(0, _SKILL_SCRIPTS)

from main import main  # noqa: E402  (skill entry point)

if __name__ == "__main__":
    main()
