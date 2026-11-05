import logging

from .candidate import Candidate
from .ice import CandidatePairStats, Connection, ConnectionClosed, TransportPolicy

__all__ = [
    "Candidate",
    "CandidatePairStats",
    "Connection",
    "ConnectionClosed",
    "TransportPolicy",
]
__version__ = "0.13.0"

# Set default logging handler to avoid "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())
