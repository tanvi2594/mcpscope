"""Core data types shared by every part of mcpscope."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from None


@dataclass(frozen=True)
class Rule:
    """A check mcpscope knows how to run. Every finding points back to one rule."""

    id: str
    title: str
    severity: Severity
    help: str


@dataclass
class Finding:
    rule: Rule
    target: str            # what was flagged, e.g. "github" or "weather / get_forecast"
    message: str           # why it was flagged, in plain words
    location: str = ""     # where inside the target, e.g. "env.GITHUB_TOKEN"
    evidence: str = ""     # a short, safe excerpt (secrets are masked)
    file: str = ""         # file the target came from, if any
    severity: Optional[Severity] = None  # defaults to the rule's severity

    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = self.rule.severity

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity.name.lower(),
            "target": self.target,
            "location": self.location,
            "message": self.message,
            "evidence": self.evidence,
            "file": self.file,
        }


@dataclass
class ScanStats:
    files: List[str] = field(default_factory=list)
    servers: int = 0
    tools: int = 0
    notes: List[str] = field(default_factory=list)
