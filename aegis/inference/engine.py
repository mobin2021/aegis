"""
Dual-mode inference client supporting remote reasoning APIs and local Ollama failover.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from ..config import AegisConfig


class InferenceEngine:
    """Manages reasoning inference with automatic local fallback."""

    def __init__(self, config: AegisConfig):
        self.config = config
        self.ollama_available = False
        if self.config.inference_mode in ("ollama", "dual") and not self.config.gemini_api_key:
            self._check_ollama_health()

    def _check_ollama_health(self) -> bool:
        """Check if local Ollama daemon is active and responding."""
        try:
            req = urllib.request.Request(f"{self.config.ollama_host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=0.8) as resp:
                if resp.status == 200:
                    self.ollama_available = True
                    return True
        except Exception:
            self.ollama_available = False
        return False

    def query_reasoning(self, prompt: str, system_prompt: str = "") -> Dict[str, Any]:
        """
        Query reasoning engine. Attempts Gemini / Cloud API first; falls back to local Ollama;
        if neither is online, uses deterministic static vulnerability heuristics.
        """
        # 0. Deterministic offline mode requested explicitly
        if self.config.inference_mode in ("offline", "heuristic"):
            heuristic_text = self._heuristic_analysis(prompt)
            return {"source": "offline-heuristic", "text": heuristic_text, "model": "aegis-core-rulebase"}

        # 1. Try Google Gemini Free API if key is present and mode allows
        if self.config.inference_mode in ("gemini", "dual") and self.config.gemini_api_key:
            try:
                result, model = self._query_gemini(prompt, system_prompt)
                return {"source": "gemini-api", "text": result, "model": model}
            except Exception as e:
                if self.config.verbose:
                    print(f"[-] Gemini API query failed ({e}). Attempting failover...")

        # 2. Try DeepSeek Cloud API if key is provided and mode allows
        if self.config.inference_mode in ("cloud", "dual") and self.config.remote_api_key:
            try:
                result = self._query_cloud(prompt, system_prompt)
                return {"source": "cloud", "text": result, "model": "deepseek-reasoner"}
            except Exception as e:
                if self.config.verbose:
                    print(f"[-] Cloud API query failed ({e}). Attempting local failover...")

        # 3. Local Fallback via Ollama (DeepSeek-R1 7B)
        if self.config.inference_mode in ("ollama", "dual") and self.ollama_available:
            try:
                result = self._query_ollama(prompt, system_prompt)
                return {"source": "ollama", "text": result, "model": self.config.ollama_model}
            except Exception as e:
                if self.config.verbose:
                    print(f"[-] Ollama query failed ({e}). Falling back to internal engine...")

        # 4. Deterministic Offline Heuristic Engine (always reliable on air-gapped systems)
        heuristic_text = self._heuristic_analysis(prompt)
        return {"source": "offline-heuristic", "text": heuristic_text, "model": "aegis-core-rulebase"}

    def _query_gemini(self, prompt: str, system_prompt: str) -> tuple[str, str]:
        """Query Google Gemini API with automatic candidate model failover."""
        candidate_models = [self.config.gemini_model, "gemini-3.5-flash", "gemini-3.7-flash", "gemini-3.8-flash"]
        # Deduplicate while preserving order
        unique_models = []
        for m in candidate_models:
            if m and m not in unique_models:
                unique_models.append(m)

        last_error = None
        full_prompt = f"{system_prompt}\n\nTask:\n{prompt}" if system_prompt else prompt

        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]

        for model in unique_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.config.gemini_api_key}"
            payload = {
                "contents": [{"parts": [{"text": full_prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 2048,
                    "thinkingConfig": {"thinkingBudget": 0}
                },
                "safetySettings": safety_settings,
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    candidates = data.get("candidates", [])
                    if candidates and candidates[0].get("content", {}).get("parts"):
                        text = candidates[0]["content"]["parts"][0]["text"].strip()
                        return text, model
            except Exception as err:
                last_error = err
                continue

        raise RuntimeError(f"All Gemini models failed. Last error: {last_error}")


    def _query_cloud(self, prompt: str, system_prompt: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.remote_api_key}",
        }
        payload = {
            "model": "deepseek-reasoner",
            "messages": [
                {"role": "system", "content": system_prompt or "You are Aegis, an expert offensive security binary triage agent."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        req = urllib.request.Request(
            self.config.remote_api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]

    def _query_ollama(self, prompt: str, system_prompt: str) -> str:
        url = f"{self.config.ollama_host}/api/generate"
        payload = {
            "model": self.config.ollama_model,
            "prompt": f"System: {system_prompt}\nUser: {prompt}",
            "stream": False,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "")

    def _heuristic_analysis(self, prompt: str) -> str:
        """Deterministic fallback analysis when neither remote API nor Ollama is reachable."""
        p_lower = prompt.lower()
        if "strcpy" in p_lower or "buffer" in p_lower or "stack" in p_lower:
            return (
                "VULNERABILITY IDENTIFIED: CWE-121 Stack-based Buffer Overflow.\n"
                "ROOT CAUSE: Unsafe memory copy via strcpy() without bounds verification.\n"
                "EXPLOITATION VECTOR: Payload exceeding buffer size overwrites saved base pointer and return address.\n"
                "RECOMMENDED PRIMITIVE: Controlled crash via 72-88 byte cyclic pattern to establish RIP control offset."
            )
        elif "printf" in p_lower or "format" in p_lower:
            return (
                "VULNERABILITY IDENTIFIED: CWE-134 Use of Externally-Controlled Format String.\n"
                "ROOT CAUSE: Direct user input passed into printf() without format specifier.\n"
                "EXPLOITATION VECTOR: Attacker-supplied %x or %s specifiers permit arbitrary stack inspection."
            )
        return (
            "VULNERABILITY IDENTIFIED: Memory Safety Invariant Violation.\n"
            "ROOT CAUSE: Unchecked buffer boundary indexing.\n"
            "EXPLOITATION VECTOR: Off-by-one boundary leak corrupting adjacent stack frame."
        )
