"""Markdown RCA report builder."""

from __future__ import annotations

from typing import Dict, List

from .models import Dimension, Observation, RCAResult


class RCAReportBuilder:
    """Render RCA results into an executive-ready Markdown report."""

    SECTION_ORDER = [
        Dimension.NETWORK_SECURITY,
        Dimension.COMPUTE_RESOURCE,
        Dimension.APPLICATION_MIDDLEWARE,
        Dimension.AWS_INFRASTRUCTURE,
        Dimension.SECURITY_THREAT,
        Dimension.OS_LAYER,
    ]

    def __init__(self, result: RCAResult):
        self.result = result

    def render(self) -> str:
        parts: List[str] = []
        parts.append(self._title())
        parts.append(self._executive_summary())
        parts.append(self._root_cause())
        parts.append(self._evidence())
        parts.append(self._timeline())
        parts.append(self._impact_assessment())
        parts.append(self._corrective_actions())
        parts.append(self._preventive_actions())
        parts.append(self._data_gaps())
        return "\n\n".join(parts)

    def _title(self) -> str:
        return f"# EC2 Root Cause Analysis – {self.result.problem.symptom}"

    def _executive_summary(self) -> str:
        impact = self.result.impact
        lines = [
            "## Executive Summary",
            "- What failed: {}".format(self.result.problem.symptom),
            "- Why it failed: {}".format(self.result.root_cause),
            "- Impact: {}".format(impact),
            "- Current status: {}".format(self.result.status),
        ]
        return "\n".join(lines)

    def _root_cause(self) -> str:
        return "## Root Cause\n{}".format(self.result.root_cause)

    def _evidence(self) -> str:
        grouped = self.result.evidence_by_dimension()
        lines = ["## Evidence & Analysis"]
        for dimension in self.SECTION_ORDER:
            lines.append(f"### {dimension.value}")
            observations = grouped.get(dimension, [])
            if not observations:
                lines.append("- No evidence collected.")
                continue
            for obs in observations:
                prefix = "(gap) " if obs.gap else ""
                lines.append(f"- {prefix}{obs.summary}")
        return "\n".join(lines)

    def _timeline(self) -> str:
        lines = ["## Timeline"]
        if not self.result.timeline:
            lines.append("- No timeline events captured.")
            return "\n".join(lines)
        for event in self.result.timeline:
            lines.append(f"- {event}")
        return "\n".join(lines)

    def _impact_assessment(self) -> str:
        env = self.result.problem.environment or "unspecified environment"
        lines = [
            "## Impact Assessment",
            f"- Scope: {env} – EC2 instance {self.result.problem.instance_id}",
            f"- Duration: incident window starting {self.result.problem.start_time or 'unknown'}",
            f"- Users affected: web clients accessing port {self.result.problem.port or 8080}",
        ]
        return "\n".join(lines)

    def _corrective_actions(self) -> str:
        lines = ["## Corrective Actions (Immediate Fixes)"]
        for action in self.result.corrective_actions:
            lines.append(f"- {action}")
        return "\n".join(lines)

    def _preventive_actions(self) -> str:
        lines = ["## Preventive Actions (Long-term)"]
        for action in self.result.preventive_actions:
            lines.append(f"- {action}")
        return "\n".join(lines)

    def _data_gaps(self) -> str:
        lines = ["## Data Gaps & Assumptions"]
        if not self.result.data_gaps:
            lines.append("- None")
        else:
            for gap in self.result.data_gaps:
                lines.append(f"- {gap}")
        return "\n".join(lines)
