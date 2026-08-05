import logging

from .candidate import Candidate
from .ice import Connection, ConnectionClosed, StunServer, TransportPolicy, TurnServer

__all__ = [
    "Candidate",
    "Connection",
    "ConnectionClosed",
    "StunServer",
    "TransportPolicy",
    "TurnServer",
]
__version__ = "0.10.2"

# Set default logging handler to avoid "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())
