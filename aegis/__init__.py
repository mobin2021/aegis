"""
Aegis: Autonomous Multi-Agent Vulnerability Assessment & Exploit Analysis Framework
Inspired by Google Project Zero methodologies for automated vulnerability discovery.
"""

__version__ = "1.0.0"
__author__ = "MD. Raisul Islam Mobin"
__license__ = "MIT"

from .manager import AegisManager
from .config import AegisConfig

__all__ = ["AegisManager", "AegisConfig"]
