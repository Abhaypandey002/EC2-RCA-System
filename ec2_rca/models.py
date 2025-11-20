from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class IssueClassification(str, Enum):
    UNREACHABLE = "unreachable"
    DEGRADED = "degraded"
    FUNCTIONAL_ERROR = "functional_error"
    UNKNOWN = "unknown"


class Dimension(str, Enum):
    NETWORK_SECURITY = "A. Network / Security"
    COMPUTE_RESOURCE = "B. Compute / Resource"
    APPLICATION_MIDDLEWARE = "C. Application / Middleware"
    AWS_INFRASTRUCTURE = "D. AWS Infrastructure"
    SECURITY_THREAT = "E. Security / Threat"
    OS_LAYER = "F. OS Layer"


@dataclass
class ProblemStatement:
    instance_id: str
    region: str
    symptom: str
    description: Optional[str] = None
    port: Optional[int] = None
    start_time: Optional[str] = None
    environment: Optional[str] = None
    known_changes: List[str] = field(default_factory=list)


@dataclass
class CheckSpec:
    name: str
    dimension: Dimension
    tool_name: str
    kwargs: Dict[str, Any]
    rationale: str


@dataclass
class Observation:
    check_name: str
    dimension: Dimension
    summary: str
    data: Any = None
    gap: bool = False


@dataclass
class RCAResult:
    problem: ProblemStatement
    classification: IssueClassification
    root_cause: str
    impact: str
    status: str
    observations: List[Observation] = field(default_factory=list)
    timeline: List[str] = field(default_factory=list)
    data_gaps: List[str] = field(default_factory=list)
    preventive_actions: List[str] = field(default_factory=list)
    corrective_actions: List[str] = field(default_factory=list)

    def evidence_by_dimension(self) -> Dict[Dimension, List[Observation]]:
        grouped: Dict[Dimension, List[Observation]] = {dim: [] for dim in Dimension}
        for obs in self.observations:
            grouped.setdefault(obs.dimension, []).append(obs)
        return grouped
