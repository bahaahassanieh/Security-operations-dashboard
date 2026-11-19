"""CVSS v3.1 base score calculator.

This implements the official CVSS v3.1 base-metric equations and the official ``roundup``
behaviour, so scores match the FIRST specification exactly. Temporal and environmental metrics
are not computed; a tester may still store a full vector string on a finding.

CVSS v4.0 vectors are validated and stored elsewhere, but their numeric score is not computed here,
because that requires the official MacroVector lookup table. The calculator UI produces v3.1.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

VERSION = "3.1"
PREFIX = "CVSS:3.1"

# Metric values from the CVSS v3.1 specification (section 7.4).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Order, label and options for each base metric, used by the calculator form.
METRICS = (
    ("AV", "Attack Vector", (("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical"))),
    ("AC", "Attack Complexity", (("L", "Low"), ("H", "High"))),
    ("PR", "Privileges Required", (("N", "None"), ("L", "Low"), ("H", "High"))),
    ("UI", "User Interaction", (("N", "None"), ("R", "Required"))),
    ("S", "Scope", (("U", "Unchanged"), ("C", "Changed"))),
    ("C", "Confidentiality", (("H", "High"), ("L", "Low"), ("N", "None"))),
    ("I", "Integrity", (("H", "High"), ("L", "Low"), ("N", "None"))),
    ("A", "Availability", (("H", "High"), ("L", "Low"), ("N", "None"))),
)
_OPTIONS = {code: {value for value, _ in options} for code, _, options in METRICS}
_METRIC_ORDER = [code for code, _, _ in METRICS]
_VECTOR_PART = re.compile(r"^([A-Z]+):([A-Z]+)$")


class CvssError(ValueError):
    """The supplied metrics or vector are not a valid CVSS v3.1 base vector."""


@dataclass(frozen=True)
class CvssResult:
    version: str
    vector: str
    base_score: float
    severity: str

    def as_dict(self) -> dict:
        return {"version": self.version, "vector": self.vector, "base_score": self.base_score, "severity": self.severity}


def severity_for(score: float) -> str:
    """Map a base score to the CVSS v3.1 qualitative rating."""
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _roundup(value: float) -> float:
    """Official CVSS v3.1 Roundup: the smallest one-decimal number not less than the input."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def compute(metrics: dict[str, str]) -> CvssResult:
    """Compute the base score from a mapping of metric code to value letter."""
    chosen = {}
    for code in _METRIC_ORDER:
        value = (metrics.get(code) or "").strip().upper()
        if value not in _OPTIONS[code]:
            raise CvssError(f"Choose a valid value for {code}.")
        chosen[code] = value

    scope_changed = chosen["S"] == "C"
    iss = 1 - (1 - _CIA[chosen["C"]]) * (1 - _CIA[chosen["I"]]) * (1 - _CIA[chosen["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[chosen["PR"]]
    exploitability = 8.22 * _AV[chosen["AV"]] * _AC[chosen["AC"]] * pr * _UI[chosen["UI"]]

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))

    vector = f"{PREFIX}/" + "/".join(f"{code}:{chosen[code]}" for code in _METRIC_ORDER)
    return CvssResult(VERSION, vector, round(score, 1), severity_for(score))


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.1/...`` base vector into its metric map, rejecting anything malformed."""
    text = (vector or "").strip()
    parts = text.split("/")
    if not parts or parts[0] != PREFIX:
        raise CvssError("A CVSS v3.1 vector must start with CVSS:3.1.")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        match = _VECTOR_PART.match(part)
        if not match:
            raise CvssError(f"Malformed metric: {part!r}.")
        code, value = match.group(1), match.group(2)
        if code in metrics:
            raise CvssError(f"Metric {code} appears twice.")
        metrics[code] = value
    missing = [code for code in _METRIC_ORDER if code not in metrics]
    if missing:
        raise CvssError(f"The vector is missing required metrics: {', '.join(missing)}.")
    return metrics


def score_vector(vector: str) -> CvssResult:
    """Validate a v3.1 vector string and compute its base score."""
    return compute(parse_vector(vector))
