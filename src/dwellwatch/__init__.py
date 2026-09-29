"""DwellWatch: catch a ransomware intrusion during dwell time, not at encryption."""

import logging

__version__ = "0.1.0"

# A library logs; the application decides where it goes. Without this, Python's last-resort handler
# would print every warning (a failed push, say) on top of what the command line already reports.
logging.getLogger(__name__).addHandler(logging.NullHandler())
