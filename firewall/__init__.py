"""prompt-injection-firewall — runtime guardrails for tool-calling agents.

The core idea: **tool output is DATA, never instructions.** Anything a tool
returns is untrusted text. This package scans it for injected instructions
before the agent acts on it.

Public API:
    from firewall import Firewall, Policy, scan, wrap_tool_output, safe_echo

    fw = Firewall()
    result = fw.scan_output("web_search", tool_output)
    if result.action == "block":
        ...  # do not let the agent see the raw output
"""

from .detectors import Finding, ScanResult, scan, DETECTOR_RULES, CATEGORIES
from .policy import Policy, Decision, decide, decide_on_text, sanitize_text
from .boundary import (
    BoundaryError,
    wrap_tool_output,
    unwrap_tool_output,
    safe_echo,
    is_wrapped,
)

__all__ = [
    "Finding",
    "ScanResult",
    "scan",
    "DETECTOR_RULES",
    "CATEGORIES",
    "Policy",
    "Decision",
    "decide",
    "decide_on_text",
    "sanitize_text",
    "BoundaryError",
    "wrap_tool_output",
    "unwrap_tool_output",
    "safe_echo",
    "is_wrapped",
]


class Firewall:
    """One object for the whole agent loop: wrap -> scan -> decide."""

    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy()

    def scan_output(self, tool_name: str, output: str) -> Decision:
        """Scan raw tool output and return the policy decision for it."""
        result = scan(output)
        return decide_on_text(output, result, self.policy)

    def scan_wrapped(self, wrapped: str) -> Decision:
        """Scan boundary-wrapped tool output.

        The boundary is validated first (tamper-evident): hostile output
        that forges a closing marker will not carry the right nonce, and
        unwrap_tool_output() rejects it with BoundaryError instead of
        letting the forgery through.
        """
        _tool_name, inner = unwrap_tool_output(wrapped)
        result = scan(inner)
        return decide_on_text(inner, result, self.policy)
