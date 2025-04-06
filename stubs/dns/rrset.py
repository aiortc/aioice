from typing import Iterator

from .name import Name
from .rdata import Rdata


class RRset:
    name: Name
    rdtype: int

    def __iter__(self) -> Iterator[Rdata]: ...

    ...
