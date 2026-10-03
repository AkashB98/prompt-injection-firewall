"""The data/instruction boundary: tool output is DATA, never instructions.

Three primitives:

- wrap_tool_output(tool_name, output): fence tool output inside a marked
  boundary block with a random nonce, so the agent loop can tell "this came
  from a tool" apart from "this is an instruction". The nonce makes the
  boundary tamper-evident: hostile output that forges a closing marker will
  not carry the right nonce, and unwrap() rejects it.
- unwrap_tool_output(wrapped): validate the boundary and recover the
  original (tool_name, output). Raises BoundaryError on tampering.
- safe_echo(text): make hostile-but-legitimate content inert — strip
  invisible characters, neutralize forged boundary markers, then wrap.

The convention this enforces: anything inside a boundary block is untrusted
data. The agent must scan it (firewall.scan) before acting on it, and must
never treat its contents as instructions.
"""

from __future__ import annotations

import re
import secrets

OPEN_FMT = "<<<TOOL-OUTPUT-DATA id={nonce} tool={tool}>>>"
CLOSE_FMT = "<<</TOOL-OUTPUT-DATA id={nonce}>>>"

_OPEN_RE = re.compile(
    r"<<<TOOL-OUTPUT-DATA id=([0-9a-f]{16}) tool=([A-Za-z0-9_.-]+)>>>"
)
_CLOSE_RE = re.compile(r"<<</TOOL-OUTPUT-DATA id=([0-9a-f]{16})>>>")


class BoundaryError(ValueError):
    """Raised when a boundary block fails validation (tampering/forgery)."""


def wrap_tool_output(tool_name: str, output: str) -> str:
    """Fence tool output in a tamper-evident data boundary."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", tool_name):
        raise ValueError(f"unsafe tool name: {tool_name!r}")
    nonce = secrets.token_hex(8)
    return (
        f"{OPEN_FMT.format(nonce=nonce, tool=tool_name)}\n"
        f"{output}\n"
        f"{CLOSE_FMT.format(nonce=nonce)}"
    )


def is_wrapped(text: str) -> bool:
    """True if the text looks like a wrapped boundary block."""
    return _OPEN_RE.search(text) is not None and _CLOSE_RE.search(text) is not None


def unwrap_tool_output(wrapped: str) -> tuple[str, str]:
    """Validate the boundary and recover (tool_name, output).

    Raises BoundaryError if the open/close markers are missing, the nonces
    do not match, or extra markers suggest a forged nested boundary.
    """
    opens = list(_OPEN_RE.finditer(wrapped))
    closes = list(_CLOSE_RE.finditer(wrapped))
    if len(opens) != 1 or len(closes) != 1:
        raise BoundaryError(
            f"expected exactly one boundary pair, found "
            f"{len(opens)} open / {len(closes)} close markers"
        )
    o, c = opens[0], closes[0]
    if o.group(1) != c.group(1):
        raise BoundaryError("boundary nonce mismatch: possible forgery")
    if not (o.end() <= c.start()):
        raise BoundaryError("boundary markers out of order")
    inner = wrapped[o.end() : c.start()]
    if _OPEN_RE.search(inner) or _CLOSE_RE.search(inner):
        raise BoundaryError("nested boundary markers inside payload: forgery")
    tool_name = o.group(2)
    # wrap() adds exactly one newline on each side; remove exactly those.
    if inner.startswith("\n"):
        inner = inner[1:]
    if inner.endswith("\n"):
        inner = inner[:-1]
    return tool_name, inner


_ZERO_WIDTH_RE = re.compile("[" + "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0xFEFF)) + "]")


def safe_echo(text: str) -> str:
    """Render untrusted text inert, then wrap it in a data boundary.

    - Strips invisible zero-width characters (the smuggling channel).
    - Neutralizes any forged boundary markers by rewriting them into a
      visible, inert form.
    - Wraps the result so downstream readers treat it as data.

    "Safe echo" means: you can quote hostile content back (for logging,
    for showing the user what the tool said) without the quote itself
    becoming an instruction or a smuggling vector.
    """
    cleaned = _ZERO_WIDTH_RE.sub("", text)
    # Neutralize forged markers: rewrite them so they no longer parse.
    cleaned = _OPEN_RE.sub(r"<<<FORGED-TOOL-DATA id=\1 tool=\2>>>", cleaned)
    cleaned = _CLOSE_RE.sub(r"<<</FORGED-TOOL-DATA id=\1>>>", cleaned)
    return wrap_tool_output("safe-echo", cleaned)
