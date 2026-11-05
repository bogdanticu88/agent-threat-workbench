// Bitwise Defence Agent Threat Workbench catalogue v0.1
// Written independently from public sources. IDs and wording are our own.

const FEATURES = [
  ["data", "Sensitive or regulated data", "Customer, personal, financial or confidential data can reach the model."],
  ["rag", "Retrieval (RAG)", "Answers draw on an index of documents or records."],
  ["untrusted", "Untrusted content", "Email, web pages, tickets, issues or uploaded files enter the context."],
  ["tools", "Tool use / actions", "The agent calls APIs or takes actions, not just answers."],
  ["mcp", "MCP servers", "Tools are reached through Model Context Protocol servers or a gateway."],
  ["plugins", "Third-party plugins or skills", "Tools, skills or servers come from public registries or vendors."],
  ["memory", "Persistent memory", "The agent remembers across sessions."],
  ["code", "Code execution", "The agent writes and runs code or shell commands."],
  ["coding", "Coding agent on workstations", "Developers run agents in IDEs or terminals with their own credentials."],
  ["browser", "Browser or computer use", "The agent drives a browser or desktop."],
  ["multi", "Multi-agent", "Agents call or delegate to other agents."],
  ["logging", "Prompt and trace logging", "Prompts, context and tool traces are stored."],
  ["selfhost", "Self-hosted or fine-tuned model", "You load model weights yourself."]
];

const HOSTING = [["api", "Hosted model API"], ["platform", "Agent platform / SaaS"], ["self", "Self-hosted model"]];
const AUTONOMY = [["suggest", "Suggests only"], ["approve", "Acts after approval"], ["auto", "Acts on its own"]];
const AUDIENCE = [["internal", "Internal staff"], ["external", "Customers / public"], ["multitenant", "Multi-tenant SaaS"]];

const FAMILIES = {
  GOV: "Governance", ID: "Identity and delegation", IN: "Input and context", TL: "Tools and actions",
  DA: "Data, retrieval and memory", OUT: "Output handling", SC: "MCP and supply chain",
  OBS: "Observability and forensics", MA: "Multi-agent"
};

const DOMAINS = ["Input and context", "Identity and delegation", "Tools and actions", "Data and memory", "MCP and supply chain", "Output", "Operations"];

// p = priority (1 = do first). ev = evidence that shows it is real. test = how to verify.
const CONTROLS = [
  {id:"GOV-1", t:"Inventory and named owner for every agent, tool and MCP server", p:1, ev:"Inventory export with owner per entry, reconciled against network discovery", test:"Pick 5 agents found in logs and trace each to an inventory entry"},
  {id:"GOV-2", t:"Change control for prompts, agent config and tool lists", p:2, ev:"Config in version control; merge approvals for the last 3 changes", test:"Attempt a direct change in the console and confirm it is blocked or alerted"},
  {id:"GOV-3", t:"Model provider terms checked: retention, training use, region", p:2, ev:"Signed DPA, zero-retention or opt-out setting screenshot, region config", test:"Review the tenant settings against the contract annually"},
  {id:"GOV-4", t:"Users know the limits and can report bad output", p:3, ev:"In-product notice and a working report channel with triage owner", test:"File a test report and time the response"},
  {id:"GOV-5", t:"Adversarial testing before release and after material change", p:1, ev:"Red-team report with injection, exfil and tool-abuse cases, dated after last change", test:"Re-run the regression suite on the current build"},
  {id:"ID-1", t:"Strong sign-in for users: MFA, bound sessions", p:1, ev:"IdP policy showing MFA and session lifetime for the assistant app", test:"Replay a session cookie from another device"},
  {id:"ID-2", t:"Each agent has its own least-privilege identity", p:1, ev:"Per-agent service principals with scoped roles, no shared keys", test:"List effective permissions per agent and compare with its task"},
  {id:"ID-3", t:"Tools run with the end user's delegated rights (on-behalf-of)", p:1, ev:"Tool calls carry the user's token or a down-scoped delegation; downstream authz checks the user", test:"As a low-privilege user, ask the agent for a resource you cannot open directly"},
  {id:"ID-4", t:"Tokens bound to one audience, never passed through", p:1, ev:"MCP servers reject tokens not issued for them; token exchange in place", test:"Send a token minted for service A to service B"},
  {id:"ID-5", t:"Short-lived credentials, no static secrets in agent runtimes", p:1, ev:"Workload identity or vault-issued creds with TTL; secret scan of agent images", test:"Search runtime env and repos for long-lived keys"},
  {id:"ID-6", t:"Agent-to-agent and agent-to-MCP calls authenticated and authorised", p:1, ev:"mTLS or OAuth on every hop; per-tool authorisation rules", test:"Call an internal MCP endpoint without credentials and as the wrong client"},
  {id:"ID-7", t:"Lifecycle for agent identities and what they create", p:2, ev:"Expiry on agent principals, tokens and created resources; deprovisioning job", test:"Find agent-created resources older than policy allows"},
  {id:"IN-1", t:"Untrusted content is read without authority to act", p:1, ev:"Architecture shows either a quarantined reader with no write, send or fetch tools, or a plan fixed before untrusted content is read (plan-then-execute); content carries a provenance tag", test:"Plant instructions in an email, document, web page and tool result; confirm none produces a tool call the user did not request. Limit: this stops actions, not misleading answers, so pair it with OUT-4"},
  {id:"IN-2", t:"Injection and jailbreak detection on inputs and tool results", p:2, ev:"Classifier in path for user input and tool output, with logged verdicts", test:"Run a public injection corpus and measure catch rate"},
  {id:"IN-3", t:"No secrets or access rules in system prompts", p:1, ev:"Prompt review showing no keys, URLs with tokens or authz logic", test:"Extract the system prompt and check what it reveals"},
  {id:"IN-4", t:"Rate, size, token and cost quotas", p:2, ev:"Per-user and per-agent quotas with alerting", test:"Drive a loop and confirm it stops at the limit"},
  {id:"TL-1", t:"Minimal tool set per agent and task", p:1, ev:"Tool allow-list per agent, reviewed against task description", test:"Ask the agent for an out-of-task action and confirm no tool exists for it"},
  {id:"TL-2", t:"Deterministic policy check on every tool call, outside the model", p:1, ev:"Policy engine logs for allow and deny decisions on tool calls", test:"Craft a call that violates policy and confirm the engine denies it"},
  {id:"TL-3", t:"High-risk tools disabled once untrusted content is in context", p:1, ev:"Taint flag in orchestrator that removes send, write and fetch tools", test:"Load a web page, then ask the agent to email data out"},
  {id:"TL-4", t:"Hard limits on action blast radius", p:1, ev:"Caps on amount, recipients, records touched and rate per action", test:"Request a bulk action above the cap"},
  {id:"TL-5", t:"Approvals show the exact resolved action, not the model's summary", p:1, ev:"Approval UI renders tool name, final arguments, recipients and data", test:"Hide a harmful argument behind a benign summary and see if the approver sees it"},
  {id:"TL-6", t:"Code runs in an ephemeral sandbox: no network, no host credentials", p:1, ev:"Sandbox config (gVisor, Firecracker or container) with egress off", test:"Run code that reads env, metadata endpoint and network"},
  {id:"TL-7", t:"Egress allow-list for agent runtimes and tools", p:1, ev:"Proxy or firewall policy with deny-by-default for agent workloads", test:"Fetch an unlisted domain from a tool"},
  {id:"TL-8", t:"Tested kill switch and containment runbook", p:2, ev:"Runbook plus a dated exercise that stopped an agent and revoked its creds", test:"Time a full stop in a tabletop or live drill"},
  {id:"DA-1", t:"Retrieval enforces source permissions at query time", p:1, ev:"ACLs synced to the index and applied per query", test:"Query as a user without access to a known document"},
  {id:"DA-2", t:"Index fed only from vetted sources, with provenance", p:2, ev:"Ingestion allow-list, source attribution on chunks, integrity checks", test:"Try to get an external document indexed"},
  {id:"DA-3", t:"Vector store protected like the data it was built from", p:2, ev:"Same classification, encryption and access controls as source systems", test:"Review who can query embeddings directly"},
  {id:"DA-4", t:"Only approved data classes reach the model", p:1, ev:"Data classification gate or DLP before prompt assembly", test:"Submit restricted data and confirm it is blocked or masked"},
  {id:"DA-5", t:"Memory scoped per user, provenance-tagged, reviewable and erasable", p:1, ev:"Memory store keyed by user with source tags and a delete path", test:"Write memory as user A and probe for it as user B"},
  {id:"DA-6", t:"Logs redacted, access-restricted and expiring", p:2, ev:"Redaction pipeline, log RBAC, retention policy", test:"Search logs for test PII after a session"},
  {id:"OUT-1", t:"Model output encoded or parameterised before reaching browser, shell, SQL or API", p:1, ev:"Output handlers use escaping and parameterised calls", test:"Get the model to emit script, shell metacharacters or SQL and check the sink"},
  {id:"OUT-2", t:"No automatic loading of external images or links; CSP on the client", p:1, ev:"Renderer blocks remote images; CSP header on chat client", test:"Have the model output a markdown image to an external host"},
  {id:"OUT-3", t:"Output filtering for sensitive data and secrets", p:2, ev:"DLP on responses with logged hits", test:"Seed a canary secret and ask for it"},
  {id:"OUT-4", t:"Answers grounded with citations; limits shown; high-stakes outputs reviewed", p:2, ev:"Citations in UI, refusal on low confidence, review step for regulated use", test:"Ask questions outside the corpus"},
  {id:"SC-1", t:"MCP servers, plugins and skills pinned and verified from an approved list", p:1, ev:"Allow-list with versions and hashes; install blocked otherwise", test:"Try installing an unlisted server on a managed device"},
  {id:"SC-2", t:"Tool descriptions reviewed and changes detected", p:1, ev:"Hash of tool manifests stored; alert on change", test:"Change a tool description in a test server and confirm the alert"},
  {id:"SC-3", t:"MCP servers isolated, bound to localhost or behind auth", p:1, ev:"Container per server, no host mounts, no 0.0.0.0 binds", test:"Port-scan workstations and hosts for MCP listeners"},
  {id:"SC-4", t:"MCP OAuth hardened: URL validation, PKCE, per-client consent", p:2, ev:"Client validates authorization endpoints; consent per client ID", test:"Point a client at a crafted authorization URL"},
  {id:"SC-5", t:"AI bill of materials and patch SLA for frameworks and servers", p:2, ev:"AIBOM with versions; SLA metrics for agent stack CVEs", test:"Pick a recent framework CVE and check exposure time"},
  {id:"SC-6", t:"Model artifacts verified: safe formats and hashes", p:2, ev:"Safetensors only; signatures or hashes checked at load", test:"Attempt to load a pickle-format model"},
  {id:"OBS-1", t:"Every agent action attributable to user, agent, input and tool", p:1, ev:"Trace schema with user, agent, prompt ref, tool, args and result", test:"Reconstruct one action end to end from logs"},
  {id:"OBS-2", t:"Tamper-evident action record kept outside the agent", p:2, ev:"Independent recorder or append-only store the agent cannot write to", test:"Compare agent-side logs with the independent record"},
  {id:"OBS-3", t:"Detection use cases deployed for agent behaviour", p:2, ev:"SIEM rules for the detections marked deployed", test:"Fire a test event for each rule"},
  {id:"OBS-4", t:"Canary tokens and decoy documents in sources and tools", p:3, ev:"Canaries placed in index, mailboxes and tool data, wired to alerting", test:"Touch a canary and confirm the alert"},
  {id:"MA-1", t:"Inter-agent messages authenticated, schema-checked and treated as untrusted", p:1, ev:"Signed messages, strict schemas, trust boundary per agent", test:"Inject a forged message between agents"}
];

const DETECTIONS = [
  ["DT-01","Injection or jailbreak flagged","Guardrail and classifier verdicts"],
  ["DT-02","Read-sensitive-then-send tool sequence","Orchestrator tool-call traces"],
  ["DT-03","Egress to a new or blocked destination","Proxy, firewall, DNS"],
  ["DT-04","Sensitive data or secrets in output","Response DLP"],
  ["DT-05","Agent identity used outside its baseline","IdP and cloud audit logs"],
  ["DT-06","Tool or MCP manifest changed","Manifest hash monitor"],
  ["DT-07","Unexpected writes to the retrieval index","Ingestion pipeline logs"],
  ["DT-08","High-impact action outlier","Business system audit logs"],
  ["DT-09","Retrieval beyond the user's entitlement","Shadow ACL check on retrieval logs"],
  ["DT-10","Unusual access to vector or log stores","Data store audit logs"],
  ["DT-11","Token or cost spike","Provider usage and billing"],
  ["DT-12","Canary or decoy touched","Canary service"],
  ["DT-13","Config or prompt changed outside the pipeline","Platform audit log"],
  ["DT-14","Unregistered agent or MCP server found","EDR, network discovery"],
  ["DT-15","Action with no matching record","Reconciliation of system logs and agent record"],
  ["DT-16","Instruction-like content written to memory","Memory store writes"],
  ["DT-17","Unexpected process or escape attempt in sandbox","Runtime security (eBPF, EDR)"],
  ["DT-18","Token used for wrong audience or widened scope","Token service and gateway logs"],
  ["DT-19","Spike in policy denials for an agent","Policy engine logs"]
];

// req: all listed features must be on. any: at least one. when: profile keys.
// L/I base likelihood and impact 1..5. mod: act | exposed | data | mt
// map: llm = OWASP LLM Top 10 (2025 IDs), asi = OWASP Top 10 for Agentic Applications 2026, atlas = MITRE ATLAS, mcp = MCP security best practices / CoSAI MCP
const THREATS = [
  {id:"T01", dom:0, t:"User overrides the assistant with direct injection or jailbreak", s:"A user types instructions that make the agent ignore its rules, reveal data or call tools it should not.", L:4, I:3, mod:["exposed"], c:["IN-3","ID-3","GOV-5"], alt:[["IN-2","OUT-3"]], opt:[], d:["DT-01"], map:{llm:["LLM01"], asi:["ASI01"], atlas:["AML.T0051.000","AML.T0054"]}},
  {id:"T02", dom:0, t:"Instructions hidden in email, pages or files hijack the agent", s:"An outsider plants text in content the agent will read. The agent treats it as instructions from its user.", req:["untrusted"], L:4, I:4, mod:["act"], c:["ID-3"], alt:[["IN-1","TL-3"],["OUT-2","TL-7"]], opt:["IN-2"], d:["DT-01","DT-02","DT-12"], map:{llm:["LLM01"], asi:["ASI01"], atlas:["AML.T0051.001"]}, cases:[{t:"EchoLeak, Microsoft 365 Copilot (CVE-2025-32711, June 2025): a crafted email led Copilot to send organisational data out with no user click.",u:"https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html"},{t:"Slack AI (August 2024): instructions posted in a public channel made answers leak data from private channels the attacker could not see.",u:"https://promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection"}]},
  {id:"T03", dom:0, t:"Tool results or MCP responses carry injected instructions", s:"A tool returns attacker-controlled text, such as an issue body or API field, and the agent follows it.", any:["tools","mcp"], L:4, I:4, mod:["act"], c:["TL-2","TL-1"], alt:[["IN-1","TL-3"]], opt:[], d:["DT-01","DT-02","DT-19"], map:{llm:["LLM01"], asi:["ASI01","ASI02"], atlas:["AML.T0051.001"]}, cases:[{t:"GitHub MCP server (May 2025): a malicious issue in a public repo made the agent copy private repository data into a public pull request.",u:"https://invariantlabs.ai/blog/mcp-github-vulnerability"}]},
  {id:"T04", dom:4, t:"Tool descriptions or schemas carry hidden instructions", s:"An MCP server ships tool metadata that tells the model to read files or send data, invisible to the user.", req:["mcp"], L:3, I:4, c:["SC-1","SC-2"], alt:[], opt:["TL-1"], d:["DT-06"], map:{llm:["LLM04"], asi:["ASI04"]}, cases:[{t:"Tool poisoning (April 2025): hidden instructions in an MCP tool description made Cursor read SSH keys and MCP config and pass them to the server.",u:"https://invariantlabs.ai/blog/mcp-security-notification"}]},
  {id:"T05", dom:4, t:"An approved server or plugin changes behaviour after approval", s:"A trusted MCP server or package update quietly adds data collection or new instructions.", any:["mcp","plugins"], L:3, I:4, c:["SC-2"], alt:[["SC-1","GOV-2"]], opt:[], d:["DT-06"], map:{llm:["LLM04"], asi:["ASI04"]}, cases:[{t:"postmark-mcp (September 2025): after 15 clean releases, version 1.0.16 of an npm MCP server added a hidden BCC copying every sent email to the publisher.",u:"https://www.bleepingcomputer.com/news/security/unofficial-postmark-mcp-npm-silently-stole-users-emails/"}]},
  {id:"T06", dom:4, t:"Malicious or look-alike MCP server, plugin or skill installed", s:"Someone installs a server from a registry that is malicious from the start or impersonates a real one.", any:["mcp","plugins","coding"], L:3, I:5, c:["SC-1"], alt:[["SC-3","TL-7"]], opt:["SC-5","GOV-1"], d:["DT-14","DT-03"], map:{llm:["LLM04"], asi:["ASI04"], atlas:["AML.T0010"]}, cases:[{t:"postmark-mcp (September 2025): an unofficial npm package copied the name and code of Postmark's real MCP server, then turned malicious.",u:"https://www.bleepingcomputer.com/news/security/unofficial-postmark-mcp-npm-silently-stole-users-emails/"}]},
  {id:"T07", dom:2, t:"Private data, untrusted content and an outbound channel meet in one agent", s:"The agent can read sensitive data, ingests attacker text and can send or fetch. Any injection becomes exfiltration.", req:["data","untrusted","tools"], L:4, I:5, mod:["act"], c:["TL-2"], alt:[["TL-3","IN-1","TL-7"]], opt:[], d:["DT-02","DT-03","DT-04"], map:{llm:["LLM01","LLM02"], asi:["ASI01","ASI02"], atlas:["AML.T0057"]}, cases:[{t:"Supabase MCP with Cursor (July 2025, research demo): a support ticket made an agent running with service-role access read a tokens table and write it back into the ticket.",u:"https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/"}]},
  {id:"T08", dom:5, t:"Data leaks through rendered markdown images or links", s:"Injected text makes the model output an image URL with data in the query string. The client fetches it.", req:["untrusted"], L:4, I:4, c:["OUT-2"], alt:[], opt:["IN-1","OUT-3"], d:["DT-03","DT-04"], map:{llm:["LLM10","LLM02"], asi:["ASI01"], atlas:["AML.T0077"]}, cases:[{t:"EchoLeak (June 2025): the exploit got past Microsoft's injection classifier and external-link redaction to move data out through the rendered response.",u:"https://www.securityweek.com/echoleak-ai-attack-enabled-theft-of-sensitive-data-via-microsoft-365-copilot/"}]},
  {id:"T09", dom:1, t:"Confused deputy: the agent uses its own rights for a user who lacks them", s:"Tools run as a powerful service account, so any user can reach data or actions through the agent.", req:["tools"], L:4, I:4, mod:["mt"], c:["ID-3"], alt:[], opt:["ID-2","TL-2"], d:["DT-05","DT-09"], map:{llm:["LLM03"], asi:["ASI03"], mcp:["Confused deputy"]}, cases:[{t:"MCPHub (GHSA-wf8q-wvv8-p8jf, 2026): the SSE endpoint took the username from the URL path without authentication, so callers could run tools as other users. Fixed in 0.12.15.",u:"https://github.com/advisories/GHSA-wf8q-wvv8-p8jf"}]},
  {id:"T10", dom:1, t:"Tokens passed through or accepted for the wrong audience", s:"An MCP server forwards the client's token downstream or accepts tokens minted for something else.", any:["mcp","multi"], L:3, I:4, c:["ID-4"], alt:[], opt:["ID-6"], d:["DT-18"], map:{asi:["ASI03"], mcp:["Token passthrough"]}},
  {id:"T11", dom:1, t:"Missing authorisation on admin functions of the agent platform or gateway", s:"A normal user calls an admin endpoint of the MCP gateway or agent platform and changes its configuration.", req:["mcp"], L:3, I:5, c:["ID-6","SC-5"], alt:[], opt:["SC-3","GOV-5"], d:["DT-05","DT-13"], map:{asi:["ASI03"], mcp:["CoSAI MCP-T1"]}, cases:[{t:"MCPHub (CVE-2025-13822): authentication bypass in versions below 0.11.0, published by CERT Polska.",u:"https://cert.pl/en/posts/2026/04/CVE-2025-13822"}]},
  {id:"T12", dom:4, t:"MCP servers exposed or unauthenticated", s:"A server listens on all interfaces or trusts localhost, so other hosts or a web page can call it.", req:["mcp"], L:3, I:5, c:["SC-3","ID-6"], alt:[], opt:["SC-4"], d:["DT-14","DT-12"], map:{asi:["ASI04"], mcp:["CoSAI MCP-T8","Local server compromise"]}, cases:[{t:"MCP Inspector (CVE-2025-49596, June 2025): no authentication between the Inspector client and its local proxy, so a malicious website could run commands on a developer's machine. Fixed in 0.14.1.",u:"https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596"}]},
  {id:"T13", dom:4, t:"OAuth flow abuse in MCP clients", s:"A malicious server returns a crafted authorization URL or skips consent, leading to code execution or token theft.", req:["mcp"], L:2, I:5, c:["SC-4"], alt:[], opt:["SC-1"], d:["DT-03"], map:{asi:["ASI04"], mcp:["Authorization URL validation"]}, cases:[{t:"mcp-remote (CVE-2025-6514, July 2025): a malicious server's authorization_endpoint value led to OS command execution on the client. Versions 0.0.5 to 0.1.15.",u:"https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/"}]},
  {id:"T14", dom:2, t:"Server-side request forgery through tools or MCP metadata", s:"The agent or MCP client fetches attacker-chosen URLs, reaching internal services or cloud metadata.", any:["tools","mcp"], L:3, I:4, c:["TL-7"], alt:[], opt:["OUT-1"], d:["DT-03"], map:{llm:["LLM10"], mcp:["SSRF"]}},
  {id:"T15", dom:2, t:"Agent has more tools, scopes or reach than its task needs", s:"Broad permissions turn any mistake or injection into a large incident.", req:["tools"], L:4, I:4, mod:["act"], c:["TL-1","ID-2"], alt:[["TL-2","TL-4"]], opt:[], d:["DT-02","DT-19"], map:{llm:["LLM03"], asi:["ASI02","ASI03"]}},
  {id:"T16", dom:2, t:"Agent goes beyond its task with no attacker involved", s:"The agent misreads intent and deletes, sends or changes things nobody asked for.", req:["tools"], L:3, I:4, mod:["act"], c:["TL-4"], alt:[["TL-2","TL-5"]], opt:["TL-8","OBS-1"], d:["DT-08","DT-19"], map:{llm:["LLM03"], asi:["ASI08","ASI10"]}, cases:[{t:"Replit (July 2025): a coding agent ran destructive commands against a live database during a declared code freeze.",u:"https://www.eweek.com/news/replit-ai-coding-assistant-failure/"}]},
  {id:"T17", dom:2, t:"Approvers rubber-stamp or are misled about what they approve", s:"Approval prompts show the model's summary, not the real call, or arrive so often people stop reading.", when:{autonomy:["approve"]}, req:["tools"], L:4, I:4, c:["TL-5"], alt:[], opt:["TL-4"], d:["DT-08"], map:{asi:["ASI09"]}},
  {id:"T18", dom:5, t:"Model output reaches a browser, shell, query or API unvalidated", s:"Generated text becomes HTML, a command or a query and runs with the application's rights.", any:["tools","code"], L:3, I:5, c:["OUT-1"], alt:[], opt:["TL-6"], d:["DT-17","DT-02"], map:{llm:["LLM10"], asi:["ASI05"]}},
  {id:"T19", dom:2, t:"Generated code escapes its sandbox or reaches the network", s:"Code the agent runs reads host credentials, cloud metadata or calls out.", req:["code"], L:3, I:5, c:["TL-6"], alt:[], opt:["TL-7","ID-5"], d:["DT-17","DT-03"], map:{asi:["ASI05"]}},
  {id:"T20", dom:1, t:"Coding agent acts with a developer's credentials on their machine", s:"An IDE or terminal agent inherits SSH keys, cloud sessions and tokens. Injected repo content drives it.", req:["coding"], L:4, I:5, c:["ID-5"], alt:[["TL-6","TL-1"]], opt:["OBS-2","SC-1"], d:["DT-14","DT-17","DT-03"], map:{asi:["ASI03","ASI05"]}, cases:[{t:"Amazon Q Developer for VS Code (July 2025): version 1.84.0 shipped with an injected prompt telling the agent to wipe local files and AWS resources. AWS says it was malformed and did not run.",u:"https://www.techradar.com/pro/amazon-ai-coding-agent-hacked-to-inject-data-wiping-commands"}]},
  {id:"T21", dom:3, t:"Retrieval returns documents the user may not read", s:"The index ignores source permissions, so answers include restricted content.", req:["rag"], L:4, I:4, mod:["data"], c:[], alt:[["DA-1","ID-3"]], opt:[], d:["DT-09"], map:{llm:["LLM09","LLM02"]}},
  {id:"T22", dom:3, t:"Poisoned documents in the index steer answers", s:"An attacker gets content indexed that carries instructions or false facts.", req:["rag"], L:3, I:4, c:["DA-2"], alt:[], opt:["IN-1","OUT-4"], d:["DT-07","DT-01"], map:{llm:["LLM05","LLM09"], atlas:["AML.T0070"]}},
  {id:"T23", dom:3, t:"Embeddings or the vector store leak their source content", s:"Direct access to vectors or chunk text exposes the documents behind them.", req:["rag"], L:2, I:3, mod:["data"], c:["DA-3"], alt:[], opt:[], d:["DT-10"], map:{llm:["LLM09"]}},
  {id:"T24", dom:3, t:"Poisoned memory persists across sessions", s:"Injected text writes a lasting instruction to memory that fires in later conversations.", req:["memory"], L:3, I:4, c:["DA-5"], alt:[], opt:["IN-1"], d:["DT-16"], map:{asi:["ASI06"]}, cases:[{t:"SpAIware, ChatGPT macOS app (September 2024): a prompt injection wrote an instruction into long-term memory that kept sending later conversations to an attacker. Fixed in 1.2024.247.",u:"https://thehackernews.com/2024/09/chatgpt-macos-flaw-couldve-enabled-long.html"}]},
  {id:"T25", dom:3, t:"Data crosses between users or tenants", s:"Shared memory, caches, indexes or sessions return one user's data to another.", any:["memory","rag","tools"], L:2, I:5, mod:["mt"], c:[], alt:[["ID-3","DA-1"]], opt:["DA-5"], d:["DT-04","DT-09"], map:{llm:["LLM02"], asi:["ASI06"]}},
  {id:"T26", dom:3, t:"Answers disclose sensitive data to the wrong person", s:"The model repeats personal or confidential data the reader should not see.", req:["data"], L:3, I:4, c:["DA-4"], alt:[["ID-3","DA-1"]], opt:["OUT-3"], d:["DT-04"], map:{llm:["LLM02"]}},
  {id:"T27", dom:6, t:"Prompt and trace logs hold sensitive data", s:"Full prompts and tool traces end up in broadly readable logs that are kept for years.", req:["logging"], L:3, I:4, mod:["data"], c:["DA-6"], alt:[], opt:[], d:["DT-10"], map:{llm:["LLM02"]}},
  {id:"T28", dom:6, t:"Model provider handles prompts outside agreed terms", s:"Prompts are kept, reviewed or used for training against your expectations or in the wrong region.", when:{host:["api","platform"]}, L:2, I:4, mod:["data"], c:["GOV-3"], alt:[], opt:["DA-4"], d:[], map:{llm:["LLM02"]}},
  {id:"T29", dom:0, t:"System prompt or hidden context extracted", s:"A user gets the model to reveal its instructions, exposing logic, internal names or secrets.", L:4, I:2, mod:["exposed"], c:["IN-3"], alt:[], opt:["OBS-4"], d:["DT-01","DT-12"], map:{llm:["LLM08"], atlas:["AML.T0056"]}},
  {id:"T30", dom:5, t:"Wrong but confident answers drive real decisions", s:"Users act on fabricated or outdated answers because they sound authoritative.", L:3, I:3, mod:["exposed"], c:["OUT-4"], alt:[], opt:["GOV-4"], d:[], map:{llm:["LLM07"], asi:["ASI09"]}, cases:[{t:"Air Canada (February 2024): a British Columbia tribunal held the airline to a bereavement refund its website chatbot described incorrectly.",u:"https://www.cbsnews.com/news/aircanada-chatbot-discount-customer"}]},
  {id:"T31", dom:0, t:"Users manipulated through an assistant they trust", s:"Injected content makes the assistant push users to click, pay or disclose something.", req:["untrusted"], L:2, I:3, mod:["exposed"], c:["OUT-2"], alt:[["IN-1","GOV-4"]], opt:[], d:["DT-01"], map:{asi:["ASI09"]}},
  {id:"T32", dom:6, t:"Runaway usage exhausts budget or capacity", s:"Loops, recursion or abuse burn tokens and API quota.", L:3, I:3, mod:["act","exposed"], c:["IN-4"], alt:[], opt:["TL-4"], d:["DT-11"], map:{llm:["LLM06"], atlas:["AML.T0034"]}},
  {id:"T33", dom:1, t:"Messages between agents spoofed or carrying instructions", s:"One agent forges or injects into messages another agent trusts.", req:["multi"], L:3, I:4, c:["MA-1"], alt:[], opt:["ID-6","IN-1"], d:["DT-02"], map:{asi:["ASI07"]}},
  {id:"T34", dom:2, t:"One agent's failure cascades through others", s:"A bad output from one agent is amplified as downstream agents act on it.", req:["multi"], L:3, I:4, mod:["act"], c:["TL-4"], alt:[["TL-8","MA-1"]], opt:[], d:["DT-19","DT-08"], map:{asi:["ASI08"]}},
  {id:"T35", dom:6, t:"Prompts, config or tool lists changed without review", s:"A console edit widens tools or weakens rules with no record or approval.", L:3, I:4, c:["GOV-2"], alt:[], opt:[], d:["DT-13"], map:{asi:["ASI10"]}},
  {id:"T36", dom:6, t:"Agents and MCP servers run with no inventory or owner", s:"Teams deploy agents and servers nobody tracks, so nobody patches or reviews them.", L:4, I:3, c:["GOV-1"], alt:[], opt:["SC-5"], d:["DT-14"], map:{asi:["ASI10"]}},
  {id:"T37", dom:6, t:"Agent actions cannot be traced to a user, agent or input", s:"After an incident nobody can say which prompt, user or document caused an action.", req:["tools"], L:4, I:3, c:["OBS-1"], alt:[], opt:["OBS-2","OBS-3"], d:["DT-15"], map:{asi:["ASI10"]}},
  {id:"T38", dom:4, t:"Flaws in the agent framework or platform exploited", s:"A vulnerable orchestration framework or low-code agent builder is reachable and exploitable.", L:3, I:5, c:["SC-5"], alt:[["SC-3","ID-2"]], opt:[], d:["DT-03","DT-12"], map:{llm:["LLM04"], asi:["ASI04"]}, cases:[{t:"Langflow (CVE-2025-3248): an unauthenticated code-validation endpoint allowed remote code execution; CISA added it to the KEV catalogue in May 2025.",u:"https://www.helpnetsecurity.com/2025/05/06/langflow-cve-2025-3248-exploited/"}]},
  {id:"T39", dom:4, t:"Tampered model weights loaded", s:"A model file from a hub carries a backdoor or code that runs on load.", req:["selfhost"], L:2, I:5, c:["SC-6"], alt:[], opt:["SC-5"], d:[], map:{llm:["LLM04","LLM05"], atlas:["AML.T0010"]}},
  {id:"T40", dom:0, t:"Browser or desktop agent hijacked by page content", s:"A page the agent visits carries instructions that make it click, type or submit on the user's behalf.", req:["browser"], L:4, I:5, mod:["act"], c:["TL-5"], alt:[["IN-1","TL-3"]], opt:["TL-7"], d:["DT-01","DT-03"], map:{llm:["LLM01"], asi:["ASI01"], atlas:["AML.T0051.001"]}},
  {id:"T41", dom:1, t:"Account takeover hands an attacker someone's assistant", s:"Stolen sessions or crafted links let an attacker use the victim's agent and its access.", L:3, I:4, mod:["exposed"], c:["ID-1"], alt:[], opt:[], d:["DT-05"], map:{asi:["ASI03"]}},
  {id:"T42", dom:1, t:"Agent identities and created resources never expire", s:"Old agent principals, tokens and the resources they made linger with live access.", req:["tools"], L:3, I:3, c:["ID-7"], alt:[], opt:["ID-5"], d:["DT-18"], map:{asi:["ASI03"]}}
];

// Attack paths. Each stage lists threats an attacker could use there.
const PATHS = [
  // from: where the path starts on the map. anchors: the component each stage plays out on.
  // req/any/cond gate the path on the profile. Stages measure prevention only; detection is reported separately.
  {id:"AP-1", t:"Planted content steals data", from:"atk", anchors:["ext","app","client"], req:["untrusted"], any:["data","rag"], needs:"untrusted content plus sensitive data or retrieval",
   stages:[["Plant instructions",["T02","T22","T24","T40"]],["Reach private data",["T26","T21","T09"]],["Get it out",["T08","T07","T14"]]]},
  {id:"AP-2", t:"Injected instructions trigger an unauthorised action", from:"atk", anchors:["ext","orch","tools"], req:["tools"], any:["untrusted","browser"], needs:"tool use plus untrusted content or browser use",
   stages:[["Inject",["T02","T03","T40"]],["Agent holds the reach",["T15","T09"]],["Action passes the gate",["T17","T18"]]]},
  {id:"AP-3", t:"Poisoned MCP supply chain", from:"atk", anchors:["reg","mcp","tools"], any:["mcp","plugins"], needs:"MCP servers or third-party plugins",
   stages:[["Bad server installed or changed",["T06","T05","T04"]],["Server sees tokens or data",["T10","T12"]],["Data or action leaves",["T07","T14"]]]},
  {id:"AP-4", t:"Cross-tenant tool execution", tAlt:"Cross-user tool execution through a shared gateway", from:"user", anchors:["mcp","app"], req:["tools"], cond:p => p.audience === "multitenant" || p.feat.includes("mcp"),
   needs:"tool use plus a multi-tenant audience or a shared MCP gateway", origin:"any signed-in user, no attacker skill needed",
   stages:[["Gateway skips authorisation",["T09","T11","T12"]],["Read another tenant's data",["T25","T26"],"Read another user's data"]]},
  {id:"AP-5", t:"Coding agent to production credentials", from:"atk", anchors:["repo","ws","ws"], req:["coding"], needs:"coding agents on workstations",
   stages:[["Injected repo or issue content",["T02","T03"]],["Agent runs with developer rights",["T20","T19","T18"]],["Credentials leave or persist",["T07","T42"]]]},
  {id:"AP-6", t:"Memory poisoning that keeps firing", from:"atk", anchors:["ext","mem","client"], req:["memory"], any:["untrusted"], needs:"persistent memory plus untrusted content",
   stages:[["Inject",["T02","T31"]],["Written to memory",["T24"]],["Fires for later sessions or users",["T25","T26"]]]},
  {id:"AP-7", t:"Agent does damage with no attacker", from:"user", anchors:["orch","tools"], req:["tools"], needs:"tool use", origin:"an ordinary request, no attacker involved",
   stages:[["Agent misreads the task",["T16","T30"]],["It has the reach to act",["T15"]]]}
];

const FRAMEWORKS = {
  llm: {name:"OWASP Top 10 for LLM Applications 2026", url:"https://genai.owasp.org/llm-top-10/", items:{LLM01:"Prompt injection",LLM02:"Sensitive information disclosure",LLM03:"Excessive agency",LLM04:"Supply chain",LLM05:"Data and model poisoning",LLM06:"Unbounded consumption",LLM07:"Misinformation",LLM08:"Hidden context exposure",LLM09:"Vector and embedding weaknesses",LLM10:"Improper output handling"}},
  asi: {name:"OWASP Top 10 for Agentic Applications 2026", url:"https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/", items:{ASI01:"Agent goal hijack",ASI02:"Tool misuse and exploitation",ASI03:"Identity and privilege abuse",ASI04:"Agentic supply chain vulnerabilities",ASI05:"Unexpected code execution (RCE)",ASI06:"Memory and context poisoning",ASI07:"Insecure inter-agent communication",ASI08:"Cascading failures",ASI09:"Human-agent trust exploitation",ASI10:"Rogue agents"}},
  atlas: {name:"MITRE ATLAS techniques", url:"https://atlas.mitre.org/techniques", items:{"AML.T0051.000":"LLM prompt injection: direct","AML.T0051.001":"LLM prompt injection: indirect","AML.T0054":"LLM jailbreak","AML.T0056":"Extract LLM system prompt","AML.T0057":"LLM data leakage","AML.T0070":"RAG poisoning","AML.T0077":"LLM response rendering","AML.T0010":"AI supply chain compromise","AML.T0034":"Cost harvesting"}},
  mcp: {name:"MCP security best practices and CoSAI MCP paper", url:"https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices", items:{"Confused deputy":"Confused deputy","Token passthrough":"Token passthrough","SSRF":"Server-side request forgery","Local server compromise":"Local MCP server compromise","Authorization URL validation":"OAuth authorization URL validation","CoSAI MCP-T1":"Improper authentication and identity","CoSAI MCP-T8":"Network binding and isolation failures"}}
};

// Overreach outcome -> threats it demonstrates. Boundary text adds more.
const OVERREACH_MAP = {
  data_theft:["T07","T15"], destruction:["T15","T16"], takeover:["T15","T09"], fraud:["T15","T17"], cost:["T32","T15"]
};
const BOUNDARY_RULES = [
  [/untrusted text/i, ["T03"]],
  [/cross(es)? tenant|cross-tenant/i, ["T25","T09"]],
  [/acts as/i, ["T09"]],
  [/no ownership check|idor/i, ["T09"]]
];
// Generic keyword rules for SARIF and other findings
const KEYWORD_RULES = [
  [/prompt.?injection|indirect injection/i, ["T02","T03"]], [/jailbreak/i, ["T01"]], [/tool.?poison/i, ["T04"]],
  [/rug.?pull|manifest change/i, ["T05"]], [/typosquat|malicious (package|server)/i, ["T06"]],
  [/exfil|data.?theft|data_theft/i, ["T07"]], [/markdown image|image render/i, ["T08"]],
  [/confused.?deputy|idor|broken object|authori[sz]ation bypass/i, ["T09"]], [/token passthrough|audience/i, ["T10"]],
  [/privilege escalation|admin endpoint/i, ["T11"]], [/unauthenticated|0\.0\.0\.0|exposed (mcp|server)/i, ["T12"]],
  [/oauth|authorization url/i, ["T13"]], [/ssrf|request forgery/i, ["T14"]], [/excessive agency|overprivileg|over-privileg/i, ["T15"]],
  [/xss|command injection|sql injection|output handling/i, ["T18"]], [/sandbox|rce|code execution/i, ["T19"]],
  [/rag|retrieval|acl/i, ["T21"]], [/poison/i, ["T22"]], [/memory/i, ["T24"]], [/cross.?tenant|tenant isolation/i, ["T25"]],
  [/pii|sensitive data|secret/i, ["T26"]], [/system prompt/i, ["T29"]], [/cost|denial of wallet|quota/i, ["T32"]]
];
