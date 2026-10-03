"""
Base worker interface for all specialized Aegis agents.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from ..config import AegisConfig


class BaseWorker(ABC):
    """Abstract Base Class for Aegis Worker Agents."""

    def __init__(self, name: str, config: AegisConfig):
        self.name = name
        self.config = config
        self.telemetry: Dict[str, Any] = {}

    @abstractmethod
    def execute(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute assigned specialized task and return structured findings."""
        pass

    def log(self, message: str) -> None:
        """Format and print agent telemetry log."""
        if self.config.verbose:
            print(f"[{self.name.upper()}] {message}")
