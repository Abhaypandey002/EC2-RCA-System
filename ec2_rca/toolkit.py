"""Diagnostic toolkit definitions for EC2 RCA."""

from dataclasses import dataclass
from typing import Any, Callable


class MissingTool(Exception):
    """Raised when a requested diagnostic tool is not provided."""


def _default_missing(*_: Any, **__: Any) -> Any:
    raise MissingTool("Tool not provided")


@dataclass
class DiagnosticToolkit:
    """Container for AWS/environment diagnostic callables.

    The host application can inject its own implementations for each callable;
    by default, a MissingTool exception will be raised to signal visibility gaps.
    """

    get_instance_details: Callable[..., Any] = _default_missing
    get_instance_status: Callable[..., Any] = _default_missing
    get_security_groups: Callable[..., Any] = _default_missing
    get_network_acls: Callable[..., Any] = _default_missing
    get_route_tables: Callable[..., Any] = _default_missing
    get_elastic_ip_mappings: Callable[..., Any] = _default_missing
    get_cloudwatch_metrics: Callable[..., Any] = _default_missing
    get_cloudwatch_alarms: Callable[..., Any] = _default_missing
    get_cloudwatch_logs: Callable[..., Any] = _default_missing
    get_cloudtrail_events: Callable[..., Any] = _default_missing
    run_ssm_command: Callable[..., Any] = _default_missing
    check_ssm_managed: Callable[..., Any] = _default_missing
    check_cloudwatch_agent_status: Callable[..., Any] = _default_missing
    get_waf_logs: Callable[..., Any] = _default_missing
    get_guardduty_findings: Callable[..., Any] = _default_missing
    get_shield_events: Callable[..., Any] = _default_missing

    def has_tool(self, name: str) -> bool:
        tool = getattr(self, name, _default_missing)
        return tool is not _default_missing
