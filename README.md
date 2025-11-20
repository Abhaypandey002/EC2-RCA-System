# EC2 RCA System

This repository provides a Python-based EC2 Root Cause Analysis orchestrator for web workloads (e.g., Nginx on port 8080). It plans diagnostics across AWS, network, compute, application, and OS layers, runs them through host-provided tools, and renders an executive-ready Markdown report.

## Key components
- `ec2_rca.orchestrator.EC2RCAOrchestrator` builds investigation plans, executes checks via injected tool callables, and derives a concise root-cause statement.
- `ec2_rca.report.RCAReportBuilder` converts investigation results into the standardized RCA report template.
- `ec2_rca.models` defines dataclasses for problem statements, check specs, observations, and RCA results.

## Usage
Inject implementations for the diagnostic tools (e.g., `get_instance_status`, `run_ssm_command`) into `DiagnosticToolkit`, then execute the orchestrator:

```python
from ec2_rca.models import ProblemStatement
from ec2_rca.orchestrator import EC2RCAOrchestrator
from ec2_rca.report import RCAReportBuilder
from ec2_rca.toolkit import DiagnosticToolkit

# Example stub tool implementations

def fake_get_instance_status(instance_id: str):
    return {"state": "running"}

def fake_get_security_groups(instance_id: str):
    return {"inbound": [{"port": 8080, "allowed": False}]}


toolkit = DiagnosticToolkit(
    get_instance_status=fake_get_instance_status,
    get_security_groups=fake_get_security_groups,
)

problem = ProblemStatement(
    instance_id="i-0123456789abcdef0",
    region="us-east-1",
    symptom="Website on port 8080 is down",
    start_time="2025-01-01T00:00:00Z",
    port=8080,
)

orchestrator = EC2RCAOrchestrator(toolkit)
result = orchestrator.run(problem)
report = RCAReportBuilder(result).render()
print(report)
```

## Tests
Run the test suite with:

```
python -m unittest
```
