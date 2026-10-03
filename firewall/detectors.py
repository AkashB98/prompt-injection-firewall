"""Heuristic detectors for injected instructions inside tool output.

Every rule here follows one hard lesson (pinned by tests): **framing, not
vocabulary.** A bare word like "urgent", "tool output", or "delete" never
fires a rule on its own. A finding requires attack framing — an override
verb, an agent-directed imperative, a smuggled payload structure, or a
decode that reveals a directive. Doc framing ("Example:", "e.g.", "to
delete a user, call ...") actively suppresses findings.

Severity order: low < medium < high.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high")

CATEGORIES = (
    "instruction_override",
    "system_prompt_override",
    "fabricated_tool_call",
    "role_confusion",
    "exfiltration",
    "encoded_payload",
)


@dataclass
class Finding:
    category: str
    rule_id: str
    severity: str  # low | medium | high
    evidence: str  # short quoted snippet, <= 140 chars
    span: tuple[int, int]
    explanation: str

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "evidence": self.evidence,
            "span": list(self.span),
            "explanation": self.explanation,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "clean" if not self.findings else "flagged"

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return max(self.findings, key=lambda f: order[f.severity]).severity

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "max_severity": self.max_severity,
            "findings": [f.to_dict() for f in self.findings],
        }


def _evidence(text: str, start: int, end: int, pad: int = 40) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    snippet = text[s:e].replace("\n", " ").replace("\r", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > 140:
        snippet = snippet[:137] + "..."
    return snippet


# ---------------------------------------------------------------------------
# Framing helpers
# ---------------------------------------------------------------------------

# Markers that say "this is an attack, not documentation".
_ATTACK_FRAMING = re.compile(
    r"(?i)\b(ignore|disregard|forget|override|bypass)\b"
    r"|\byou must\b"
    r"|\bdo this\b|\brun this\b|\bexecute (this|immediately)\b"
    r"|\bimmediately\b|\bright now\b|\basap\b|\bact now\b"
    r"|\binstead\b"
    r"|\bdo not (follow|obey)\b"
)

# Markers that say "this is documentation, not an attack". When doc framing
# appears near a payload candidate, the finding is suppressed.
# NOTE: the word markers carry a (?<!\.) guard — without it, a domain like
# "evil.example" counts as doc framing and vetoes a real attack.
_DOC_FRAMING = re.compile(
    r"(?i)(?<!\.)\b(example|e\.g\.|for instance|such as|syntax|usage|sample|demo)\b"
    r"|to \w+ a user, call"  # "to delete a user, call delete_user(...)"
    r"|```"  # fenced code sample
)

_URGENCY = re.compile(
    r"(?i)\burgent\b|\bimmediately\b|\basap\b|\bact now\b"
    r"|\bright now\b|\btime[-\s]sensitive\b|\bemergency\b"
)


def _has_attack_framing(text: str, start: int, end: int, window: int = 150) -> bool:
    s = max(0, start - window)
    e = min(len(text), end + window)
    return _ATTACK_FRAMING.search(text, s, e) is not None


def _has_doc_framing(text: str, start: int, end: int, window: int = 150) -> bool:
    s = max(0, start - window)
    e = min(len(text), end + window)
    return _DOC_FRAMING.search(text, s, e) is not None


# ---------------------------------------------------------------------------
# R1 — instruction_override: directives aimed at the agent
# ---------------------------------------------------------------------------

_R1_PATTERNS: list[tuple[str, str, str]] = [
    # (rule_id, regex, explanation)
    (
        "override-target",
        r"(?i)\b(ignore|disregard|forget|override|bypass)\s+(all\s+)?"
        r"(your|the|these|prior|previous)\s+"
        r"(instructions?|directives?|rules?|guidelines?|system prompts?)\b",
        "Tells the agent to drop its own instructions — the classic "
        "instruction-override move.",
    ),
    (
        "override-safety",
        r"(?i)\bignore\s+(all\s+)?(verification|verification steps|safety|"
        r"safety checks|policy|policies)\b",
        "Tells the agent to skip verification or safety checks.",
    ),
    (
        "agent-imperative",
        r"(?i)\byou must\s+(now\s+)?(call|run|execute|send|email|delete|remove|"
        r"ignore|disregard|forget|override|follow)\b",
        "Second-person imperative aimed at the agent ('you' = the agent "
        "reading this tool output), ordering a sensitive action.",
    ),
    (
        "disobey-user",
        r"(?i)\bdo not\s+(follow|obey|listen to)\s+(the\s+)?"
        r"(user'?s?|original|initial)\s+(request|instructions?)\b",
        "Tells the agent to disobey the user's own request.",
    ),
]


def _rule_instruction_override(text: str) -> list[Finding]:
    out: list[Finding] = []
    for rule_id, pattern, explanation in _R1_PATTERNS:
        for m in re.finditer(pattern, text):
            out.append(
                Finding(
                    category="instruction_override",
                    rule_id=f"instruction_override.{rule_id}",
                    severity="high",
                    evidence=_evidence(text, m.start(), m.end()),
                    span=(m.start(), m.end()),
                    explanation=explanation,
                )
            )
    return out


# ---------------------------------------------------------------------------
# R2 — system_prompt_override: attempts to replace the agent's identity
# ---------------------------------------------------------------------------

_R2_PATTERNS: list[tuple[str, str, str]] = [
    (
        "new-system-prompt",
        r"(?i)\b(your\s+)?new\s+system\s+prompt\s*:",
        "Declares a replacement system prompt inside tool output.",
    ),
    (
        "replace-instructions",
        r"(?i)\b(replace|override|update|set)\s+your\s+"
        r"(system\s+prompt|instructions|persona)\s+(with|to)\b",
        "Orders the agent to swap its instructions for attacker text.",
    ),
    (
        "from-now-on",
        r"(?i)\bfrom now on[,\s]+you are\b",
        "Reassigns the agent's identity going forward.",
    ),
    (
        "role-reassign",
        r"(?i)\byour\s+(new\s+)?(role|identity)\s+is\s+now\b",
        "Reassigns the agent's role inside tool output.",
    ),
    (
        "you-are-now",
        r"(?i)\byou are now\b",
        "Reassigns who the agent is, mid-conversation, from tool output.",
    ),
]


def _rule_system_prompt_override(text: str) -> list[Finding]:
    out: list[Finding] = []
    for rule_id, pattern, explanation in _R2_PATTERNS:
        for m in re.finditer(pattern, text):
            out.append(
                Finding(
                    category="system_prompt_override",
                    rule_id=f"system_prompt_override.{rule_id}",
                    severity="high",
                    evidence=_evidence(text, m.start(), m.end()),
                    span=(m.start(), m.end()),
                    explanation=explanation,
                )
            )
    return out


# ---------------------------------------------------------------------------
# R3 — fabricated_tool_call: tool-call instructions smuggled in data
# ---------------------------------------------------------------------------

_R3_PAYLOADS: list[tuple[str, str, str]] = [
    (
        "function-call-syntax",
        r"\b(call|run|execute|invoke)\s+[A-Za-z_][\w.]*\s*\(",
        "Function-call syntax embedded in tool output.",
    ),
    (
        "run-prefix",
        r"(?i)^[ \t]*(run|execute)\s*:\s*\S",
        "'run:' / 'execute:' command prefix embedded in tool output.",
    ),
    (
        "rm-rf",
        r"(?i)\brm\s+-rf?\s+\S",
        "Destructive rm command embedded in tool output.",
    ),
    (
        "curl-pipe-sh",
        r"(?i)\bcurl\s+\S+\s*\|\s*(ba)?sh\b",
        "curl-piped-to-shell pattern embedded in tool output.",
    ),
    (
        "tool-call-marker",
        r"(?i)\b(function_call|tool_call|call_tool)\b",
        "Explicit tool-call protocol marker embedded in tool output.",
    ),
]


def _rule_fabricated_tool_call(text: str) -> list[Finding]:
    out: list[Finding] = []
    for rule_id, pattern, explanation in _R3_PAYLOADS:
        for m in re.finditer(pattern, text, re.MULTILINE):
            start, end = m.start(), m.end()
            # Payload alone is not enough: "to delete a user, call
            # delete_user(admin)" is help text. Require attack framing near
            # the payload, and let doc framing veto it.
            if _has_doc_framing(text, start, end):
                continue
            if not _has_attack_framing(text, start, end):
                continue
            out.append(
                Finding(
                    category="fabricated_tool_call",
                    rule_id=f"fabricated_tool_call.{rule_id}",
                    severity="high",
                    evidence=_evidence(text, start, end),
                    span=(start, end),
                    explanation=explanation + " Attack framing nearby turns "
                    "a code sample into a smuggled instruction.",
                )
            )
    return out


# ---------------------------------------------------------------------------
# R4 — role_confusion: tool output pretending to be the assistant
# ---------------------------------------------------------------------------

_ROLE_CLAIM = re.compile(
    r"(?i)\bas an?\s+(AI|artificial intelligence)\s+(assistant|agent|language model)\b"
    r"|\bas (a|your)\s+helpful\s+assistant\b"
)

_ASSERTED_ACTION = re.compile(
    r"(?i)\bI('ve| have)\s+(already\s+)?"
    r"(completed|processed|deleted|sent|refunded|refunds?|approved|executed|"
    r"cancelled|transferred|wired)\b"
    r"|\byou should\b|\byou must\b|\bI recommend you\b"
    r"|\bI am (the|your)\s+(system|admin|administrator|developer)\b"
)


def _rule_role_confusion(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _ROLE_CLAIM.finditer(text):
        window_end = min(len(text), m.end() + 200)
        a = _ASSERTED_ACTION.search(text, m.end(), window_end)
        if not a:
            continue  # bare role mention (e.g. FAQ text) is not an attack
        out.append(
            Finding(
                category="role_confusion",
                rule_id="role_confusion.impersonated-assistant",
                severity="medium",
                evidence=_evidence(text, m.start(), a.end()),
                span=(m.start(), a.end()),
                explanation="Tool output claims the assistant's identity and "
                "then asserts a completed action or issues a directive — "
                "the tool is impersonating the agent.",
            )
        )
    return out


# ---------------------------------------------------------------------------
# R5 — exfiltration: instructions to move sensitive data out
# ---------------------------------------------------------------------------

_SENSITIVE_NOUN = (
    r"credentials?|passwords?|secrets?|api[\s_-]?keys?|tokens?|"
    r"private keys?|customer (data|list|records)|user data|"
    r"contents of|database dumps?|\.env\b|env files?|"
    r"social security|ssn\b"
)

_SEND_VERB = r"send|email|e-mail|forward|upload|post|transmit|exfiltrate"

_DESTINATION = (
    r"to\s+[\w.+-]+@[\w.-]+\.\w+"  # email address
    r"|to\s+https?://\S+"  # URL
    r"|\bvia\s+POST\b"
)

_R5_SELF_FRAMING = re.compile(
    rf"(?i)\bPOST\s+the\s+({_SENSITIVE_NOUN})\b"
    rf"|\bexfiltrate\b"
)


def _rule_exfiltration(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[int, int]] = set()

    def add(start: int, end: int, explanation: str) -> None:
        key = (start, end)
        if key in seen:
            return
        seen.add(key)
        out.append(
            Finding(
                category="exfiltration",
                rule_id="exfiltration.send-sensitive-out",
                severity="high",
                evidence=_evidence(text, start, end),
                span=(start, end),
                explanation=explanation,
            )
        )

    for m in _R5_SELF_FRAMING.finditer(text):
        add(
            m.start(),
            m.end(),
            "Self-framing exfiltration directive ('POST the contents of ...' "
            "/ 'exfiltrate') inside tool output.",
        )

    noun_re = re.compile(rf"(?i)\b({_SENSITIVE_NOUN})\b")
    verb_re = re.compile(rf"(?i)\b({_SEND_VERB})\b")
    dest_re = re.compile(rf"(?i)({_DESTINATION})")

    for nm in noun_re.finditer(text):
        # A sensitive noun alone is just documentation ("Your API key is
        # stored in the .env file"). Require a send verb AND a destination
        # nearby — that triple is the exfiltration shape.
        s = max(0, nm.start() - 120)
        e = min(len(text), nm.end() + 120)
        vm = verb_re.search(text, s, e)
        dm = dest_re.search(text, s, e)
        if vm and dm:
            start = min(vm.start(), nm.start(), dm.start())
            end = max(vm.end(), nm.end(), dm.end())
            add(
                start,
                end,
                "Send-verb + sensitive-data noun + external destination "
                "inside tool output: an instruction to move secrets out.",
            )
    return out


# ---------------------------------------------------------------------------
# R6 — encoded_payload: smuggled / obfuscated directives
# ---------------------------------------------------------------------------

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_B64_DIRECTIVE_HINTS = re.compile(
    r"(?i)\b(ignore|disregard|forget|override|delete|send|run|execute|"
    r"system prompt|instructions?|exfiltrate|password|rm\s+-rf)\b"
)

_ZERO_WIDTH = re.compile("[" + "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0xFEFF)) + "]")

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_COMMENT_DIRECTIVE_HINTS = re.compile(
    r"(?i)\b(ignore|disregard|delete|run|execute|send|system prompt|"
    r"instructions?|override|password|secret)\b"
)

# Cyrillic / Greek lookalikes -> latin. Only the pairs attackers actually use.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q",
    "һ": "h", "ո": "n", "ԝ": "w", "Ь": "b", "К": "k", "М": "m",
    "Н": "h", "Т": "t", "В": "b", "Е": "e", "О": "o", "Р": "p",
    "С": "c", "Х": "x", "Α": "a", "Ε": "e", "Ο": "o", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Τ": "t", "Χ": "x", "Ζ": "z",
    "а́": "a",
}
_HOMOGLYPH_TARGETS = {
    "ignore", "delete", "run", "execute", "send", "system",
    "instructions", "override", "prompt", "password", "disregard",
}


def _try_b64_decode(blob: str) -> str | None:
    blob = blob.strip()
    if len(blob) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 8:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in " \t\n")
    if printable / len(text) < 0.85:
        return None
    return text


def _rule_encoded_payload(text: str) -> list[Finding]:
    out: list[Finding] = []

    # R6a — base64 blobs that decode to directives. A blob decoding to
    # innocent text is NOT a finding (pinned by test).
    for m in _B64_CANDIDATE.finditer(text):
        decoded = _try_b64_decode(m.group(0))
        if decoded is None:
            continue
        if _B64_DIRECTIVE_HINTS.search(decoded):
            snippet = decoded[:60].replace("\n", " ")
            out.append(
                Finding(
                    category="encoded_payload",
                    rule_id="encoded_payload.base64-directive",
                    severity="high",
                    evidence=f"base64 decodes to: {snippet!r}",
                    span=(m.start(), m.end()),
                    explanation="Base64 blob in tool output decodes to an "
                    "instructional directive — a smuggled payload.",
                )
            )

    # R6b — zero-width characters (invisible smuggling channel).
    zw = _ZERO_WIDTH.findall(text)
    if zw:
        m = _ZERO_WIDTH.search(text)
        assert m is not None
        out.append(
            Finding(
                category="encoded_payload",
                rule_id="encoded_payload.zero-width",
                severity="low",
                evidence=f"{len(zw)} invisible zero-width character(s) "
                "in tool output (shown stripped in evidence)",
                span=(m.start(), m.start() + 1),
                explanation="Zero-width characters are invisible to humans "
                "but visible to the model — a classic smuggling channel.",
            )
        )

    # R6c — HTML comments hiding directives. Benign comments are not findings.
    for m in _HTML_COMMENT.finditer(text):
        inner = m.group(1)
        if _COMMENT_DIRECTIVE_HINTS.search(inner):
            out.append(
                Finding(
                    category="encoded_payload",
                    rule_id="encoded_payload.html-comment",
                    severity="medium",
                    evidence=_evidence(text, m.start(), m.end()),
                    span=(m.start(), m.end()),
                    explanation="HTML comment in tool output hides an "
                    "instructional directive from human reviewers.",
                )
            )

    # R6d — homoglyph / lookalike substitution.
    for m in re.finditer(r"[^\x00-\x7F]{1}\S*|\S*[^\x00-\x7F]\S*", text):
        word = m.group(0)
        if not any(c in _CONFUSABLES for c in word):
            continue
        mapped = "".join(_CONFUSABLES.get(c, c) for c in word).lower()
        mapped = re.sub(r"[^a-z]", "", mapped)
        if mapped in _HOMOGLYPH_TARGETS:
            out.append(
                Finding(
                    category="encoded_payload",
                    rule_id="encoded_payload.homoglyph",
                    severity="medium",
                    evidence=_evidence(text, m.start(), m.end()),
                    span=(m.start(), m.end()),
                    explanation=f"Lookalike characters spell '{mapped}' — "
                    "a directive keyword disguised to dodge naive filters.",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------

_RULES: list[tuple[str, object]] = [
    ("instruction_override", _rule_instruction_override),
    ("system_prompt_override", _rule_system_prompt_override),
    ("fabricated_tool_call", _rule_fabricated_tool_call),
    ("role_confusion", _rule_role_confusion),
    ("exfiltration", _rule_exfiltration),
    ("encoded_payload", _rule_encoded_payload),
]

DETECTOR_RULES = {name: fn for name, fn in _RULES}


def _bump_severity(sev: str) -> str:
    order = {"low": "medium", "medium": "high", "high": "high"}
    return order[sev]


def scan(text: str) -> ScanResult:
    """Run every detector rule over tool-output text.

    Urgency language ("urgent", "ASAP", ...) never creates a finding on its
    own — it only amplifies the severity of findings that already fired.
    """
    if not isinstance(text, str):
        raise TypeError(f"scan() expects str, got {type(text).__name__}")
    findings: list[Finding] = []
    for _name, rule in _RULES:
        findings.extend(rule(text))
    findings.sort(key=lambda f: (f.span[0], f.span[1]))

    # Urgency amplifier: social-engineering pressure raises severity, but a
    # bare "is this urgent?" with no payload stays silent (pinned by test).
    if findings and _URGENCY.search(text):
        for f in findings:
            f.severity = _bump_severity(f.severity)

    return ScanResult(findings=findings)
