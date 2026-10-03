"""
Configuration management for Aegis dual-mode inference and toolchains.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AegisConfig:
    """Core runtime configuration for Aegis agents."""

    # Target
    target_path: str = ""
    target_type: str = "binary"  # "binary", "source", or "network"

    # Dual-mode Inference
    inference_mode: str = "dual"  # "cloud", "ollama", or "dual"
    ollama_host: str = field(default_factory=lambda: os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "deepseek-r1:7b"))
    remote_api_key: Optional[str] = field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", None))
    remote_api_url: str = "https://api.deepseek.com/v1/chat/completions"

    # Fuzzing & Triage Parameters
    max_fuzz_seconds: int = 30
    crash_timeout_ms: int = 500
    mutation_intensity: int = 3

    # Output paths
    output_dir: str = "aegis_output"
    poc_output_path: str = "aegis_output/poc.py"
    report_output_path: str = "aegis_output/audit_report.json"

    # Logging
    verbose: bool = True
