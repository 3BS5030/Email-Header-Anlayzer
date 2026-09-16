# main.py
# Desktop entry point for the Email Header Analyzer.
# Usage:  python main.py [path-to-.eml]
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())