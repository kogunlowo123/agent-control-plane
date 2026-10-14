# Who approved the agent that is running right now?

Naming your agents is easy. Showing which build of each one is running, who approved it, what policy it runs under, and how to stop it in seconds is harder.

**The problem.** Agents now come from LangGraph, CrewAI, AutoGen, Google ADK, Microsoft Agent Framework and Strands, owned by different teams on shared clusters. Deploy scripts record no intent, hand edits go unnoticed, and an emergency stop means paging whoever has kubectl.

**Why it matters.** Change control, separation of duties and incident containment do not go away because the workload reasons with a model.

**The flow we built:** Registry → Identity → Policy → Runtime → Observability.

1. Registry: agents, tools and versions with owners, risk tier and lifecycle. Tools are pinned by schema digest; images by sha256.
2. Identity: every deployed version gets its own workload identity in our identity fabric, bound to its service account and image digest.
3. Policy: signed policy bundles mounted into each workload; high-risk versions need two approvers, and nobody approves their own change.
4. Runtime: desired state reconciled to Kubernetes, with drift reported and reverted. Framework adapters give all six frameworks one run contract.
5. Observability: metrics, traces and a signed audit chain; MCP tools and an A2A agent let responders query status or pull the kill switch.

**Practices.** The kill switch is durable: zero replicas, deny-all network, suspended credentials, and a second officer to release it. Agent runtimes check it before every run and fail closed.

**Tradeoffs.** Reconciliation adds API load. Per-version identities add churn. Our managed-runtime target is designed, not built, because it controls less of the host.

**Value.** Audits become queries, not archaeology, and one call stops an agent everywhere.

**Future.** Agents will run on managed runtimes and clusters at once; the control plane stays the system of record.

Should a security team stop an agent on its own, or only behind a second approval?

Repo: https://github.com/kogunlowo123/agent-control-plane

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #AIGovernance #MCP #A2A #PlatformEngineering
