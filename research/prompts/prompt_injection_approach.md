# Deep Research Prompt: Prompt-Injection Checker for Agent-Adjacent Files

## Background

I'm a solo developer who uses Claude Code heavily across multiple Python projects, with a typical stack of: `uv` for deps, ruff/pytest, Pydantic AI agents calling OpenAI/Anthropic, AWS Lambda deployments via CDK, and Airtable/Salesforce/Notion as systems of record. EvaluateCDL — a serverless evaluator for venture applications using a 3-call agent pipeline — is the **reference project** I'll use to ground answers, but the deliverable should be **portable to any similarly shaped Python project I run** (research codebases, internal tools, other agent pipelines), not bespoke to EvaluateCDL.

**The threat I want to defend against:** *prompt injection embedded in text that ends up shaping an LLM's behavior.* Three concrete vectors:

1. **Agent-facing files committed (or about to be committed) to a repo** — project-level agent-instruction files, project-level memory or context files, plan files, research artefacts, READMEs, code comments, prompt templates, eval datasets. Anything an agent will load into its context window, either automatically or because I open it during a session.
2. **Live MCP server outputs** flowing into agent context. I currently use MCP servers including (non-exhaustive): Notion, Airtable, Gmail, Google Drive, Google Calendar, Slack, PitchBook, and **a Memory MCP I'm building for Claude Code**. Each can surface third-party content with attacker-controlled text. The Memory MCP is special: it both *reads from* and *writes to* a persistent store, so a single bad write becomes a persistent injection that affects every future session.
3. **External user-supplied data flowing through application LLM calls** at runtime. Acknowledge this vector but it's out of scope for the checker — design for it separately.

Primary defence I want from this research: **a checker I can drop into any project to scan agent-adjacent files for injection attempts.** Pre-commit is my preferred runtime because it stops bad text before it lands in `main`, but I am explicitly **open to designs that exceed the pre-commit budget** if a heavier scan is substantially better — for example a CI-only deep audit, an editor/save-time hook, an MCP-output interceptor, or a daemon that watches the memory directory. Tell me when "more aggressive than pre-commit" is the right answer.

**Important context on web research:** I never let Claude Code (or any local agent) perform direct web searches. All open-ended research happens via Anthropic's Claude chat interface in deep-research mode, and **I manually review every result before any of it lands on disk in a project I work on**. This means:
- The checker's job is *defence in depth* against research artefacts I might paste in despite review, not the only line of defence.
- I won't accept a recommended solution that itself wants to fetch the web at commit time or scan time.
- Detector models / rule packs that ship with the tool are fine; tool calls to live web services are not.

## Project Structure (Generic)

The checker should target files at categories of paths, not specific paths. The categories are:

- **Agent-instruction files** — files an agent loads automatically as system or project guidance (project-level and user-level).
- **Agent-memory files** — files an agent loads as durable cross-session context, including content written by the Memory MCP I'm building. Often a directory of small per-topic files plus an index file.
- **Plan / scratchpad files** — Markdown files I draft alongside the agent describing upcoming work.
- **Research artefact files** — prompts I write to send to deep-research, and results pasted back from deep-research or copied from MCP responses.
- **Prompt-template source code** — Python (or other language) modules whose string contents become the system prompt for an LLM call.
- **Eval / fixture datasets** — YAML/JSON files holding example inputs that get fed to LLMs during evaluation runs.
- **Ordinary application source** — code, comments, docstrings.
- **Configuration files** — agent-runtime settings, hook definitions, permission allowlists.

Some of these live inside a repo (so a pre-commit hook sees them naturally). Some live outside the repo (user-level instruction file, agent memory directory) but still steer the agent on this project — the checker may need to scan those too, on a different schedule.

EvaluateCDL is one example shape: it has a project-level instruction file, a memory directory referenced by an index file, a Cursor-managed plans directory, a prompt-template module, a YAML eval dataset, and several MCP integrations. The recommendations should generalise to any project with that overall shape.

## What I Need to Learn

### 1. Threat Taxonomy and Detection Signals

A concrete checklist of injection patterns the checker should look for, **with rationale per item** so I can judge edge cases:

- **Direct override patterns**: "ignore previous / above / prior instructions", "disregard the system prompt", "you are now …", "new instructions:", role-reset language, fake `<|im_start|>` / `<|system|>` / `<system>` / `[INST]` tokens, fake `Human:` / `Assistant:` turn markers, fake `<system-reminder>` / `<important>` / hook-output tags that mimic Claude Code's own context scaffolding.
- **Indirect / camouflaged injection**: instructions hidden in code comments, in docstrings, in YAML literal blocks, in HTML comments inside Markdown, in alt-text, in collapsed `<details>` sections, in zero-width or right-to-left override unicode (`U+200B`, `U+200C`, `U+200D`, `U+202E`, `U+2066–U+2069`), in homoglyphs, in white-on-white CSS embedded in HTML.
- **Encoded payloads**: base64/hex/rot13 blobs above some entropy threshold, especially when adjacent to instruction-like prose ("decode and run …").
- **Tool-targeting payloads** specific to agent contexts: mentions of shell execution, file edits, git pushes, network egress, "save the API key in `~/.bashrc`", "create a hook that …", "add to settings.json", "post to https://…", "read this URL".
- **MCP-specific markers**: text claiming to be from a privileged source ("# system instructions from Notion admin", "MCP server message:"), or text mimicking MCP wrapper conventions.
- **Memory-specific markers**: text claiming to be a saved memory, or imperatives written *as if* the user had typed them ("the user prefers that you …", "remember that …"), which can sneak into a memory store via a write tool the agent itself controls.
- **Obfuscation tells**: large stretches of text inside otherwise-data files; unusually long lines; unusually high non-ASCII ratio; large diff additions to instruction or memory files coming from a non-interactive process (e.g., a tool result, not a human keystroke).

For each category: **what is the false-positive risk on legitimate instruction-heavy prose** (since instruction files genuinely contain imperatives), and **how should detection severity differ across the file categories listed in "Project Structure"**?

### 2. Existing Tools and Libraries

State of the art (late-2025 / early-2026) for *static* prompt-injection scanning of files (not runtime guarding of LLM calls). For each candidate: licensing, latency, install footprint (`uv`-friendly preferred), Windows compatibility, whether usable as a CLI on a directory tree:

- **Meta Prompt-Guard** (e.g., 22M / 86M / multilingual variants) — small classifier; CPU-feasible.
- **Llama Guard 3 / 4** — bigger, broader policy.
- **Lakera Guard** / **Rebuff** / **Vigil** / **NeMo Guardrails** — most are runtime LLM proxies. Any usable as static file scanners?
- **garak** (NVIDIA) — primarily a red-team fuzzer. Reusable detectors?
- **`detect-secrets`-style entropy scanners** — borrowable for encoded payloads?
- **`bandit` / `semgrep` rule sets** that target prompt-injection patterns in source code.
- **Pure regex / heuristic libraries** — anything maintained, or do I roll my own?

I want a comparison table I can act on, including a note when the right answer is "no good off-the-shelf option exists for this layer; build it."

### 3. Architecture: Pre-Commit vs. Heavier Alternatives

I'm pre-commit-biased but **not pre-commit-married**. Tell me where pre-commit is the right venue and where it isn't:

- **Pre-commit hook**: scans staged changes only, fast, blocks at commit. Best for cheap regex / unicode / entropy layers. What's the realistic budget on a 50-file commit?
- **CI deep audit**: runs heavier classifier or LLM-judge over the full tree on a schedule or on every PR. Worth it for instruction and memory files specifically?
- **Editor / save-time hook**: catches text the moment it lands, before it even reaches a commit. Useful when files are written by an agent tool rather than by a human typing.
- **Memory-write interceptor**: the Memory MCP I'm building has a privileged seat — it's the *only* path by which memories get written. Should the checker live there as well, gating writes? What's the integration shape?
- **Watcher daemon over the memory / plans directories**: catches edits made outside any of the above paths.
- **Periodic full-tree audit** with a stronger model than the live checker (still local, see Constraints).

Also: how should these layers compose? Is it sensible to run a cheap pre-commit and a heavy nightly CI? When does adding the heavier layer actually catch things the cheap layer misses, vs. just duplicating it?

For the Memory MCP specifically: **what's the canonical defence for a memory store?** Content-addressable hashes with a manifest of approved entries? A "this memory was written during a real interactive turn, not from a tool result" provenance flag? A diff-style review prompt before any write commits? I want concrete patterns.

### 4. Detector Implementation Choices

Assuming a layered detector (cheap regex → unicode scan → entropy scan → ML classifier on flagged spans only):

- **Regex layer**: a starter rule pack — concrete patterns, not prose. Each rule with severity, applicable file categories (using the categories in "Project Structure"), and an example string it would catch.
- **Unicode layer**: which code-point ranges are worth flagging on sight? Confusables/homoglyph detection — a maintained Python library, or a hand-rolled scan over the Unicode confusables table?
- **Entropy layer**: thresholds for flagging probable base64/hex blobs without flooding on legitimate hashes, JWTs, UUIDs, or cloud resource identifiers.
- **Classifier layer**: per-call latency for Prompt-Guard-class models on CPU on a Windows laptop; quantized / ONNX builds; license suitability for use inside a private-repo commit hook.
- **Policy / context layer**: how to encode "this category of file legitimately contains imperatives, but flag X is still suspicious here" — a rule grammar, glob-keyed config blocks, frontmatter opt-out markers, or per-line escape comments.
- **Output format**: SARIF, plain text, GitHub-annotation-friendly. I want results to read well in the terminal *and* in CI logs.

### 5. Application to the Reference Project (and How to Generalise)

Use EvaluateCDL as the worked example, but write the recommendation as a **template**. For each file category in "Project Structure":

- A default rule profile (which detector layers run; which categories block vs. warn vs. silent).
- The reasoning for that profile (what's the threat? what's the false-positive risk?).
- How the profile would change for a different project shape (e.g., a research notebook repo with no MCPs, or a heavily MCP-driven repo with no LLM agents in production).

Specifically address:
- **Instruction files**: protecting against injected instructions while tolerating legitimate ones.
- **Memory files** (incl. files my Memory MCP will produce): provenance, hash manifests, write-time review.
- **Plan / scratchpad files**: low-trust because often co-authored with an agent.
- **Research artefacts** (the prompt-and-result pair pattern I use): given my web-research workflow (deep-research in Claude chat → manual review → paste in), what residual threats remain, and what should the checker still catch even after my manual review?
- **Prompt-template source code**: protecting against silent edits to the system prompt — diff-only check, hash pinning, codeowner-style approval, or all three?
- **Eval / fixture datasets**: these *deliberately* contain user-supplied prose; the checker should catch classic injection markers but tolerate raw narrative.
- **Ordinary source code**: lower priority; what's the minimum useful coverage?

### 6. Bypass and Audit Trail

Every blocking checker eventually needs an escape hatch. Design one that's hard to abuse:

- In-line override marker syntax (and where it's allowed vs. forbidden).
- An allowlist file with hashes of approved findings.
- A commit-message convention that records *why* a finding was overridden.
- A periodic audit step that re-checks the allowlist (in case a once-approved finding becomes risky after surrounding context changes).

### 7. Stretch / Out of Scope (Note Only)

Briefly: runtime guards on LLM calls themselves; built-in mitigations the host agent (Claude Code) already provides that the checker shouldn't duplicate; integration with code-signing or commit-signing for instruction/memory files.

## Constraints

- **Solo developer**, Windows 11 + Git Bash + PowerShell. Tooling must work on Windows; no Linux-only assumptions.
- **Python 3.12, `uv` for deps**. Pure-Python detectors strongly preferred; compiled wheels OK if `uv` resolves them on Windows.
- **Pre-commit budget**: ≤5s wall-clock on a 50-file commit. Heavier layers may run elsewhere.
- **Low false-positive bar is hard-required.** Instruction and memory files are full of legitimate imperatives. The bias should be toward catching the *out-of-place* imperative, not the frequent one.
- **No outbound network at scan time.** No third-party API for content review. Local detector models OK; live web calls not OK. This mirrors my no-web-search rule for Claude Code itself.
- **Reversibility**: any commit-blocking failure must have a documented per-line or per-file bypass with an audit trail.
- **Portability**: the recommendation must work as a drop-in for other projects with similar shape, not just one repo. Configuration should be sharable across projects with minimal per-project overrides.

## Desired Output

A practical guide that ends with code I can copy in. Specifically:

1. **Threat taxonomy table** — categories from §1, with example payloads and the file categories where each matters.
2. **Tool comparison table** — candidates from §2 scored on latency, install footprint, Windows-compat, license, and false-positive rate on instruction-heavy prose.
3. **Recommended architecture** — one diagram + short rationale: which detectors run in which venue (pre-commit, CI, save-time hook, MCP write interceptor, daemon), in what order, with what early-exit behaviour. Be explicit when a venue heavier than pre-commit is the right call.
4. **A starter detector rule pack** — concrete regexes, unicode ranges, and entropy thresholds in a config-file format I can drop into a project.
5. **Working scaffolding** — the small Python CLI that implements the detectors, plus the `.pre-commit-config.yaml` (or equivalent) and any CI / save-time / Memory-MCP integration glue. Show file contents, not descriptions.
6. **Per-category policy template** — for each file category in "Project Structure", the default rule profile, the rationale, and notes on how to adapt it for adjacent project shapes.
7. **Memory-store specific recommendations** — concrete patterns the Memory MCP should adopt internally to protect itself from injection-via-saved-memory.
8. **Bypass / allowlist mechanism** — exact syntax and a worked override example.
9. **One worked example end-to-end** — apply the checker to a sample file that contains both legitimate instruction-like prose and a smuggled injection, and show the output, including how the legitimate-mention case is distinguished.
10. **Honest limitations section** — what classes of attack this checker will *not* catch, and what the next layer of defence should be.