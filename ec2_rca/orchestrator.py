"""Orchestrator that drives EC2 root-cause investigations."""

from __future__ import annotations

from typing import List

from .models import (
    CheckSpec,
    Dimension,
    IssueClassification,
    Observation,
    ProblemStatement,
    RCAResult,
)
from .toolkit import DiagnosticToolkit, MissingTool


class EC2RCAOrchestrator:
    """Plans and executes EC2 RCA playbooks with a focus on web workloads."""

    def __init__(self, toolkit: DiagnosticToolkit):
        self.toolkit = toolkit

    def classify_issue(self, problem: ProblemStatement) -> IssueClassification:
        symptom = problem.symptom.lower()
        if any(keyword in symptom for keyword in ["timeout", "unreachable", "refused", "down"]):
            return IssueClassification.UNREACHABLE
        if any(keyword in symptom for keyword in ["slow", "latency", "degraded", "intermittent"]):
            return IssueClassification.DEGRADED
        if any(keyword in symptom for keyword in ["5xx", "error", "502", "504", "functional"]):
            return IssueClassification.FUNCTIONAL_ERROR
        return IssueClassification.UNKNOWN

    def build_plan(self, problem: ProblemStatement) -> List[CheckSpec]:
        """Create an ordered list of diagnostic checks."""

        port = problem.port or 8080
        plan: List[CheckSpec] = [
            CheckSpec(
                name="Instance status",
                dimension=Dimension.AWS_INFRASTRUCTURE,
                tool_name="get_instance_status",
                kwargs={"instance_id": problem.instance_id},
                rationale="Baseline EC2 status and reachability.",
            ),
            CheckSpec(
                name="SSM management",
                dimension=Dimension.AWS_INFRASTRUCTURE,
                tool_name="check_ssm_managed",
                kwargs={"instance_id": problem.instance_id},
                rationale="Confirms SSM access for deeper OS/app checks.",
            ),
            CheckSpec(
                name="Security groups",
                dimension=Dimension.NETWORK_SECURITY,
                tool_name="get_security_groups",
                kwargs={"instance_id": problem.instance_id},
                rationale=f"Validate inbound/outbound rules cover application port {port}.",
            ),
            CheckSpec(
                name="Network ACLs",
                dimension=Dimension.NETWORK_SECURITY,
                tool_name="get_network_acls",
                kwargs={"instance_id": problem.instance_id},
                rationale="Ensure subnet ACLs allow web and management traffic.",
            ),
            CheckSpec(
                name="Route tables",
                dimension=Dimension.NETWORK_SECURITY,
                tool_name="get_route_tables",
                kwargs={"instance_id": problem.instance_id},
                rationale="Confirm egress/ingress routing is intact.",
            ),
            CheckSpec(
                name="Elastic IP / DNS",
                dimension=Dimension.NETWORK_SECURITY,
                tool_name="get_elastic_ip_mappings",
                kwargs={"instance_id": problem.instance_id},
                rationale="Resolve address mappings for public access.",
            ),
            CheckSpec(
                name="CloudWatch metrics",
                dimension=Dimension.COMPUTE_RESOURCE,
                tool_name="get_cloudwatch_metrics",
                kwargs={
                    "instance_id": problem.instance_id,
                    "metric_name": "CPUUtilization",
                    "period": 60,
                    "start_time": problem.start_time,
                    "end_time": None,
                },
                rationale="Identify compute pressure around the incident.",
            ),
            CheckSpec(
                name="CloudWatch alarms",
                dimension=Dimension.AWS_INFRASTRUCTURE,
                tool_name="get_cloudwatch_alarms",
                kwargs={"instance_id": problem.instance_id},
                rationale="Capture alarms triggered during the window.",
            ),
            CheckSpec(
                name="Nginx status",
                dimension=Dimension.APPLICATION_MIDDLEWARE,
                tool_name="run_ssm_command",
                kwargs={
                    "instance_id": problem.instance_id,
                    "commands": ["systemctl status nginx || service nginx status"],
                },
                rationale="Confirm web server is running and healthy.",
            ),
            CheckSpec(
                name="Application listener",
                dimension=Dimension.APPLICATION_MIDDLEWARE,
                tool_name="run_ssm_command",
                kwargs={
                    "instance_id": problem.instance_id,
                    "commands": ["ss -tulpn | grep :{} || netstat -tulpn | grep :{}".format(port, port)],
                },
                rationale="Validate application port binding (default 8080).",
            ),
            CheckSpec(
                name="OS firewall",
                dimension=Dimension.APPLICATION_MIDDLEWARE,
                tool_name="run_ssm_command",
                kwargs={
                    "instance_id": problem.instance_id,
                    "commands": ["iptables -L -n | grep {} || ufw status".format(port)],
                },
                rationale="Detect host-level firewall blocking the application port.",
            ),
            CheckSpec(
                name="Nginx/app logs",
                dimension=Dimension.APPLICATION_MIDDLEWARE,
                tool_name="get_cloudwatch_logs",
                kwargs={
                    "log_group_name": f"/var/log/nginx/{problem.instance_id}",
                    "start_time": problem.start_time,
                    "end_time": None,
                    "filter_pattern": "?ERROR ?5xx",
                },
                rationale="Collect error logs around the failure window.",
            ),
            CheckSpec(
                name="CloudTrail changes",
                dimension=Dimension.AWS_INFRASTRUCTURE,
                tool_name="get_cloudtrail_events",
                kwargs={
                    "lookup_attributes": {"ResourceName": problem.instance_id},
                    "start_time": problem.start_time,
                    "end_time": None,
                },
                rationale="Find config changes (SG, NACL, reboots) near the incident.",
            ),
            CheckSpec(
                name="WAF activity",
                dimension=Dimension.SECURITY_THREAT,
                tool_name="get_waf_logs",
                kwargs={"resource_id": problem.instance_id, "start_time": problem.start_time, "end_time": None},
                rationale="Detect blocked or throttled requests indicating abuse.",
            ),
            CheckSpec(
                name="GuardDuty findings",
                dimension=Dimension.SECURITY_THREAT,
                tool_name="get_guardduty_findings",
                kwargs={"instance_id": problem.instance_id, "start_time": problem.start_time, "end_time": None},
                rationale="Identify brute force or reconnaissance affecting the host.",
            ),
            CheckSpec(
                name="Shield events",
                dimension=Dimension.SECURITY_THREAT,
                tool_name="get_shield_events",
                kwargs={"resource_arn": problem.instance_id, "start_time": problem.start_time, "end_time": None},
                rationale="Capture DDoS events impacting availability.",
            ),
            CheckSpec(
                name="Kernel/OOM logs",
                dimension=Dimension.OS_LAYER,
                tool_name="run_ssm_command",
                kwargs={
                    "instance_id": problem.instance_id,
                    "commands": ["dmesg | tail -n 50", "grep -i oom /var/log/messages || true"],
                },
                rationale="Check for kernel errors or OOM kills tied to downtime.",
            ),
        ]
        return plan

    def _run_check(self, spec: CheckSpec) -> Observation:
        tool = getattr(self.toolkit, spec.tool_name, None)
        if tool is None:
            return Observation(spec.name, spec.dimension, f"Tool {spec.tool_name} unavailable", gap=True)
        try:
            data = tool(**spec.kwargs)
            summary = self._summarize_data(spec, data)
            return Observation(spec.name, spec.dimension, summary, data=data)
        except MissingTool as exc:
            return Observation(spec.name, spec.dimension, f"{spec.tool_name} not supplied: {exc}", gap=True)
        except Exception as exc:  # noqa: BLE001
            return Observation(spec.name, spec.dimension, f"{spec.tool_name} failed: {exc}", gap=True)

    def _summarize_data(self, spec: CheckSpec, data: object) -> str:
        if data is None:
            return f"{spec.name}: no data returned"
        if isinstance(data, str):
            preview = data.splitlines()[0][:120]
            return f"{spec.name}: {preview}"
        if isinstance(data, dict):
            keys = ", ".join(sorted(data.keys()))
            return f"{spec.name}: keys => {keys}" if keys else f"{spec.name}: empty response"
        if isinstance(data, list):
            return f"{spec.name}: {len(data)} records"
        return f"{spec.name}: collected {type(data).__name__}"

    def _derive_root_cause(self, observations: List[Observation], problem: ProblemStatement) -> str:
        port = problem.port or 8080
        for obs in observations:
            if obs.dimension == Dimension.NETWORK_SECURITY and obs.data:
                sg_data = obs.data if isinstance(obs.data, dict) else {}
                inbound = sg_data.get("inbound") if isinstance(sg_data, dict) else None
                if inbound:
                    blocked = [rule for rule in inbound if rule.get("port") == port and not rule.get("allowed", True)]
                    if blocked:
                        return (
                            f"Inbound port {port} blocked in security groups, preventing access to the web application."
                        )
            if obs.check_name == "Nginx status" and isinstance(obs.data, dict):
                if not obs.data.get("active", True):
                    reason = obs.data.get("reason", "service is inactive")
                    return f"Nginx service down: {reason}."
            if obs.check_name == "Application listener" and isinstance(obs.data, dict):
                if not obs.data.get("listening", True):
                    return f"Application is not listening on port {port}."
            if obs.dimension == Dimension.COMPUTE_RESOURCE and isinstance(obs.data, dict):
                cpu = obs.data.get("max_cpu")
                if cpu and cpu >= 90:
                    return "Sustained CPU saturation on EC2 instance causing request timeouts and errors."
            if obs.dimension == Dimension.OS_LAYER and isinstance(obs.data, dict):
                if obs.data.get("oom_killed"):
                    return "Processes were killed by the kernel OOM killer, stopping the web service."
        return "Root cause inconclusive due to insufficient data."

    def run(self, problem: ProblemStatement) -> RCAResult:
        classification = self.classify_issue(problem)
        plan = self.build_plan(problem)
        observations = [self._run_check(spec) for spec in plan]

        data_gaps = [obs.summary for obs in observations if obs.gap]
        root_cause = self._derive_root_cause(observations, problem)

        timeline = []
        if problem.start_time:
            timeline.append(f"{problem.start_time} – Issue reported")
        timeline.extend([f"{obs.check_name}: {obs.summary}" for obs in observations if not obs.gap])

        preventive_actions = [
            "Add automated guardrails to prevent unapproved security group or NACL edits.",
            "Ensure CloudWatch Agent and SSM are installed for telemetry and command execution.",
            "Alert on sustained CPU, memory, and 5xx trends for web workloads.",
        ]
        corrective_actions = [
            "Restart Nginx/application service and validate port 8080 reachability.",
            "Reinstate required security group rules for web traffic.",
            "If compute saturation observed, right-size the instance or enable auto scaling.",
        ]

        impact = "Web application on EC2 experienced availability/performance issues on port {}.".format(
            problem.port or 8080
        )

        status = "mitigated" if "inconclusive" not in root_cause.lower() else "ongoing"

        return RCAResult(
            problem=problem,
            classification=classification,
            root_cause=root_cause,
            impact=impact,
            status=status,
            observations=observations,
            timeline=timeline,
            data_gaps=data_gaps,
            preventive_actions=preventive_actions,
            corrective_actions=corrective_actions,
        )
