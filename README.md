# Agent Threat Workbench

A threat model for AI agents that you can actually work with.

Describe your deployment: where the model runs, how much it is allowed to do on its own, who uses it, and what it touches (retrieval, tools, MCP servers, memory, code execution, other agents). The workbench tells you which threats apply, how they chain into attack paths, which controls would break those paths soonest, and what evidence would show a control is real.

**Live:** https://bogdanticu88.github.io/agent-threat-workbench/

## What it does

- **42 threats** across input and context, identity and delegation, tools and actions, data and memory, MCP and supply chain, output handling and operations. Each threat has a scenario, a risk rating, the controls that close it, the detections that catch it, framework mappings and, where one exists, a public case.
- **6 attack paths** that chain threats the way real incidents did. Each path has explicit prerequisites, so it only appears when your deployment can actually be attacked that way. A path is broken when every threat on any one of its stages is mitigated, and the tool points at the stage with the fewest missing controls. Detection coverage is shown per path but kept separate from prevention: an attack that gets logged still succeeded.
- **Graded controls.** Not in place, partial, implemented or verified. Verified only counts when you write down the evidence. Controls change a threat's status; they never quietly lower its rating.
- **Scanner evidence.** Import [Overreach](https://github.com/bogdanticu88/OverReach) JSON or SARIF, any SARIF 2.1.0 file, or a simple findings list. Evidence grades carry through: reachable on the spec, simulated, or proven. A threat marked mitigated that a validated finding proves exploitable is flagged as a conflict.
- **Outputs for a review.** Markdown report, threat register CSV, remediation tickets for Jira or ServiceNow, a risk acceptance register with owners and review dates, snapshots to show progress, and a JSON assessment file to save and reload.
- **Framework coverage** against the OWASP Top 10 for LLM Applications, the OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS and the MCP security guidance.

## Privacy

It is one static HTML file. No backend, no analytics, no cookies. Your answers stay in your browser's local storage, and the assessment file is how you move them anywhere else.

## Run it locally

Open `index.html` in a browser. That's it.

## Caveats

Version 0.2. Ratings are an assessment aid, not advice for your specific system. The framework mappings are ours: check them against the current releases before you cite them in an audit.

## Want the paths tested for real?

This shows what could go wrong. An assessment shows what actually does. [Bitwise Defence](https://bitwisedefence.com) tests where an agent's authority ends and hands engineers reproducible findings and fixes. contact@bitwisedefence.com
