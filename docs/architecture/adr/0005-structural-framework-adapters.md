# ADR-0005: Framework adapters typed against invocation shapes, not packages

- Status: Accepted
- Date: 2026-10-14

## Context

The platform must run agents built with LangGraph, CrewAI, AutoGen, Google
ADK, Microsoft Agent Framework and AWS Strands behind one run contract.
Depending on all six SDKs would bloat the control plane, couple its release
cadence to theirs, and pull conflicting transitive dependencies.

## Decision

- Each adapter declares a `typing.Protocol` for the exact invocation API it
  uses (`ainvoke`, `kickoff_async`, `run(task=..., cancellation_token=...)`,
  `run_async(user_id, session_id, new_message)`, `run(messages, thread=...)`,
  `invoke_async(prompt)`) and reads results by attribute or key.
- Where a framework requires one of its own types as input (ADK `Content`,
  AutoGen `CancellationToken`), the agent image injects a factory.
- Tests use fakes that reproduce each framework's documented object shapes.
- `PlatformRunner` holds everything framework independent: kill-switch check
  with the agent's credential, timeout, step budget, ContentGuard screening.

## Consequences

- The control plane installs none of the frameworks; agent images pin the
  framework version they were tested with.
- A breaking change in a framework's result shape surfaces in that agent's
  own CI, not as a control-plane dependency conflict.
