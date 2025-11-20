import unittest

from ec2_rca.models import Dimension, ProblemStatement
from ec2_rca.orchestrator import EC2RCAOrchestrator
from ec2_rca.report import RCAReportBuilder
from ec2_rca.toolkit import DiagnosticToolkit


class OrchestratorIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.problem = ProblemStatement(
            instance_id="i-0123456789abcdef0",
            region="us-east-1",
            symptom="Website on port 8080 is down",
            start_time="2025-01-01T00:00:00Z",
            port=8080,
        )

        def fake_get_instance_status(instance_id: str):  # noqa: ARG001
            return {"state": "running"}

        def fake_check_ssm_managed(instance_id: str):  # noqa: ARG001
            return {"managed": True}

        def fake_get_security_groups(instance_id: str):  # noqa: ARG001
            return {"inbound": [{"port": 8080, "allowed": True}]}

        def fake_get_network_acls(instance_id: str):  # noqa: ARG001
            return {"rules": []}

        def fake_get_route_tables(instance_id: str):  # noqa: ARG001
            return {"routes": []}

        def fake_get_elastic_ip_mappings(instance_id: str):  # noqa: ARG001
            return {"public_ip": "203.0.113.10"}

        def fake_get_cloudwatch_metrics(**kwargs):  # noqa: ANN003
            return {"max_cpu": 45}

        def fake_get_cloudwatch_alarms(instance_id: str):  # noqa: ARG001
            return []

        def fake_run_ssm_command(instance_id: str, commands):  # noqa: ARG001
            if "status nginx" in commands[0]:
                return {"active": True}
            if "ss -tulpn" in commands[0]:
                return {"listening": False}
            if "iptables" in commands[0]:
                return {"blocked": False}
            return {}

        def fake_get_cloudwatch_logs(**kwargs):  # noqa: ANN003
            return ["[error] failed to bind to port"]

        def fake_get_cloudtrail_events(**kwargs):  # noqa: ANN003
            return []

        def fake_get_waf_logs(**kwargs):  # noqa: ANN003
            return []

        def fake_get_guardduty_findings(**kwargs):  # noqa: ANN003
            return []

        def fake_get_shield_events(**kwargs):  # noqa: ANN003
            return []

        def fake_os_logs(**kwargs):  # noqa: ANN003
            return {"oom_killed": False}

        self.toolkit = DiagnosticToolkit(
            get_instance_status=fake_get_instance_status,
            check_ssm_managed=fake_check_ssm_managed,
            get_security_groups=fake_get_security_groups,
            get_network_acls=fake_get_network_acls,
            get_route_tables=fake_get_route_tables,
            get_elastic_ip_mappings=fake_get_elastic_ip_mappings,
            get_cloudwatch_metrics=fake_get_cloudwatch_metrics,
            get_cloudwatch_alarms=fake_get_cloudwatch_alarms,
            run_ssm_command=fake_run_ssm_command,
            get_cloudwatch_logs=fake_get_cloudwatch_logs,
            get_cloudtrail_events=fake_get_cloudtrail_events,
            get_waf_logs=fake_get_waf_logs,
            get_guardduty_findings=fake_get_guardduty_findings,
            get_shield_events=fake_get_shield_events,
        )

    def test_orchestrator_identifies_listener_issue(self) -> None:
        orchestrator = EC2RCAOrchestrator(self.toolkit)
        result = orchestrator.run(self.problem)

        self.assertIn("not listening on port", result.root_cause)
        grouped = result.evidence_by_dimension()
        self.assertIn(Dimension.APPLICATION_MIDDLEWARE, grouped)
        self.assertGreater(len(grouped[Dimension.APPLICATION_MIDDLEWARE]), 0)

        report = RCAReportBuilder(result).render()
        self.assertIn("EC2 Root Cause Analysis", report)
        self.assertIn("Corrective Actions", report)

    def test_data_gaps_recorded_when_missing_tools(self) -> None:
        incomplete_toolkit = DiagnosticToolkit(get_instance_status=lambda instance_id: {"state": "running"})
        orchestrator = EC2RCAOrchestrator(incomplete_toolkit)
        result = orchestrator.run(self.problem)

        self.assertTrue(result.data_gaps)
        self.assertIn("not supplied", " ".join(result.data_gaps))


if __name__ == "__main__":
    unittest.main()
