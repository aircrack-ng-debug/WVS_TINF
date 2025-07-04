from abc import ABC, abstractmethod
from typing import List
from wvs.scanner.models import Issue  # Assuming Issue is in this path


class BaseScannerModule(ABC):
    """
    Abstract base class for all scanner modules.
    It defines the contract for scanner module implementations.
    """
    NAME: str = "Unnamed Scanner Module"

    def __init__(self, timeout: int = 5):
        """
        Initializes the base scanner module.

        Args:
            timeout: Timeout for network requests in seconds.
        """
        self.timeout = timeout

    @abstractmethod
    def scan(self, target_url: str) -> List[Issue]:
        """
        Performs a scan on the given target URL and returns a list of found issues.

        Args:
            target_url: The URL to scan.

        Returns:
            A list of Issue objects.
        """
        pass
