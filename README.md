# WinOps Guard

**Headless Windows Operations, powered by AI**

> WinOps Guard is an AI SRE for Windows - it detects, explains, and safely remediates incidents without RDP.

WinOps Guard is an early prototype of an **AI-native, headless Windows operations platform**.

It removes RDP, Event Viewer, and manual log inspection from incident response by converting Windows Server state into **machine-readable signals and actionable decisions**.

**Goal:** operate Windows infrastructure without logging in.

---

## Problem

Windows operations today still rely on:

- RDP and Event Viewer
- Manual log inspection and copy/paste into tickets or chats
- Human-driven incident triage
- Slow MTTR, on-call burnout, fragile and expensive ops

Millions of Windows Servers still run critical workloads across finance, healthcare, manufacturing, and government - yet most modern ops tooling is Linux-first and cloud-native, and largely ignores Windows-specific pain.

---

## Market context

- Tens of millions of Windows Server instances are still operating globally
- Highly concentrated in regulated, slow-moving industries
- High operational cost, low automation penetration
- Pain is deep, persistent, and largely unsolved

This is a large, neglected market.

Primary buyers are MSPs and enterprises paying per-server operational costs.

---

## Solution

Treat Windows operations as **headless**:

1. Collect operational signals directly from Windows internals
2. Convert them into structured, AI-readable data
3. Perform automated triage and reasoning
4. Surface decisions through APIs and chat tools
5. Execute approved remediation safely and auditably

This repository provides the **first primitive** of that system: a safe, auditable signal -> decision -> action loop for Windows operations.

---

## What this repository provides (current)

A **Windows-only CLI toolchain** that queries the native Windows Event Log using `wevtapi` and emits **AI-friendly JSON**, enabling:

- Automated incident triage
- LLM-based root cause analysis
- Policy-driven remediation workflows
- Removal of RDP from incident response paths

### Current capabilities

- Query Application event log entries from the last N minutes
- Fetch events in batches
- Render each event to XML and human-readable messages
- Emit structured JSON per event:
  - `timeGenerated`
  - `level`
  - `eventId`
  - `source`
  - `message`

---

## Why this matters

Windows Event Logs are:

- Structured (XML-based)
- Extremely rich in operational signal
- Locked behind GUI tools and RDP workflows

By exposing them as data, incidents become **programmable**.

This enables:

- Machine-driven triage
- AI-assisted reasoning
- Auditable, repeatable operations
- Less human intervention and reduced on-call load

---

## What this is NOT

To avoid confusion:

- Not a monitoring dashboard
- Not another log shipper
- Not a PowerShell wrapper
- Not a general-purpose AI agent

WinOps Guard is an **operations execution layer**, not a visualization tool.

---

## Why existing tools fail on Windows ops

| Existing approach | Limitation |
| --- | --- |
| Datadog / New Relic | Alerting only, no remediation loop |
| PowerShell scripts | Manual, brittle, human-driven |
| RDP + Event Viewer | GUI-locked, non-automatable |
| Generic AI agents | Unsafe, no Windows domain constraints |

WinOps Guard focuses on **safe, narrow, Windows-native operations**.

---

## Why now?

Before LLMs:

- Logs could be collected
- But reasoning and decision-making stayed human

With LLMs:

- Logs become explainable system state
- Root cause analysis can be automated
- Remediation can be proposed with confidence and auditability

Windows ops has remained stuck in a 2010 workflow. LLMs make autonomous Windows operations finally possible.

---

## Initial focus

- IIS failures and Windows service outages
- Approved restart-based remediation
- MTTR reduction for MSP-style operations
- Safe, auditable automation for production Windows servers

---

## Target users

- MSPs managing dozens to hundreds of Windows Servers
- Enterprises with long-lived Windows infrastructure
- Teams fatigued by RDP-driven, on-call-heavy operations

---

## Architecture (current)

```text
Windows Event Log
  |
WinOps Guard (collector)
  |
Structured JSON
  |
LLM-based triage
  |
Approval gate
  |
Safe remediation
  |
Slack / API / Control Plane
```

---

## Usage

### Build: collector

```powershell
go build -o winopsguard.exe .
```

### Run: collector

```powershell
.\winopsguard.exe -minutes 60 -max 200
```

### Triage CLI (LLM)

```powershell
go build -o winopsguard-triage.exe ./cmd/winopsguard-triage
setx OPENAI_API_KEY "..."
# or
setx GEMINI_API_KEY "..."

.\winopsguard.exe -minutes 60 -max 200 |
  .\winopsguard-triage.exe -provider openai
```

### Slack notification

```powershell
go build -o winopsguard-notify-slack.exe ./cmd/winopsguard-notify-slack
setx SLACK_WEBHOOK_URL "https://hooks.slack.com/services/XXX/YYY/ZZZ"

.\winopsguard.exe -minutes 60 -max 200 |
  .\winopsguard-triage.exe -provider openai |
  .\winopsguard-notify-slack.exe

.\winopsguard.exe -minutes 60 -max 200 |
  .\winopsguard-triage.exe -provider openai |
  .\winopsguard-notify-slack.exe -dry-run
```

Exit codes (notify-slack):

- `0`: posted / no-op (`info`) / dry-run
- `2`: missing env, invalid input, HTTP failure, other errors

### Safe remediation (IIS)

```powershell
go build -o winopsguard-remediate-iis.exe ./cmd/winopsguard-remediate-iis

.\winopsguard.exe -minutes 60 -max 200 |
  .\winopsguard-triage.exe -provider openai |
  .\winopsguard-remediate-iis.exe
```

This command will prompt for explicit approval before it runs `iisreset`.

### Example output (collector)

```json
[
  {
    "timeGenerated": "2025-12-17T06:51:17Z",
    "level": "Information",
    "eventId": 1040,
    "source": "MsiInstaller",
    "message": "Beginning a Windows Installer transaction..."
  }
]
```

---

## Safety model

- No automatic remediation by default
- All actions require explicit approval
- Narrow, whitelisted actions only
- Full auditability of proposed and executed actions

WinOps Guard is designed to reduce operational risk, not introduce it.

---

## Roadmap

WinOps Guard will evolve into a full headless Windows Ops platform:

- Always-on Windows agent (native Windows Service)
- Central control plane
- Policy-driven remediation
- AI-assisted and approved recovery actions
- Fully headless, no-RDP workflows

Long-term vision: AI SRE for Windows infrastructure.

---

## Non-goals

- General-purpose AI agent
- Arbitrary command execution
- Replacement for human operators

WinOps Guard augments operators - it does not remove accountability.

---

## Implementation notes

- Native `wevtapi` (no PowerShell dependency)
- Proper Win32 handle management
- Errors surfaced explicitly (no panics)
- Designed for long-running agent use

---

## Team

Built by engineers with hands-on experience operating Windows-based infrastructure in production environments.

This project comes from firsthand exposure to RDP-driven, on-call-heavy Windows operations that modern tooling ignores.

---

## License

TBD (MIT / Apache-2.0 planned)
