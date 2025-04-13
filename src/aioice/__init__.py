import logging

from .candidate import Candidate
from .ice import Connection, ConnectionClosed, TransportPolicy

__all__ = ["Candidate", "Connection", "ConnectionClosed", "TransportPolicy"]
__version__ = "0.10.1"

# Set default logging handler to avoid "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())
