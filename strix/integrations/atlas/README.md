# Asset Atlas bridge (`strix.integrations.atlas`)

Asset Atlas (local asset-inventory system) owns orchestration of the combined
pipeline: its planner publishes `atlas.task.strix_scan` tasks onto its NATS
JetStream backbone; this package is the Strix-side worker that consumes those
tasks, runs a headless Strix scan against the controlled loopback fixture
named in the task, and publishes results back as `atlas.event.*` observations.
Atlas's recorder/projections then own status, results and history.

## Trust boundaries (same rules as Asset Atlas CONTRACT.md)

- **Loopback-only targets.** Every task target is resolved and required to be
  loopback; the scan is launched against the pinned literal IP
  (`guard.assert_loopback_url`). Public addresses raise before anything runs.
- **Fixed scan profiles.** The bus carries a registry key
  (`web-fixture-quick`, `web-fixture-standard`) - never raw Strix CLI flags.
  Unknown profiles and unexpected task keys are rejected
  (`strix.run_rejected` event, message acked).
- **Findings are hypotheses.** Every `strix.finding` carries
  `hypothesis: true` and `check_class: "agentic"`. Nothing is a verified
  vulnerability until a human reviews it.
- **This worker never writes the Atlas log.** It only publishes events.

## LLM access (endpoint-abstracted)

Scan subprocesses inherit the operator's environment, never the bus:

| Variable | Meaning |
| --- | --- |
| `STRIX_LLM` | model id (any LiteLLM route) |
| `LLM_API_KEY` | credential for hosted routes |
| `LLM_API_BASE` | OpenAI-compatible base URL - point at a local/self-hosted model (e.g. Ollama, vLLM, llama.cpp server) and **no external account is needed** |

`LLM_API_BASE` must be loopback unless `ATLAS_STRIX_ALLOW_REMOTE_LLM=1` is set
(bridge-side guard so scan prompts cannot be redirected to an arbitrary host).
With no model configured the CLI runner refuses to start - loudly, nothing is
faked. A deterministic stub endpoint for wiring tests/CI:
`python -m strix.integrations.atlas.stub_llm --port 8401` (clearly labeled:
not a model, fixed responses).

## Running

```bash
pip install -e '.[atlas]'            # adds nats-py (optional extra)
nats-server -js -a 127.0.0.1 -p 4222 # Atlas backbone (or the Atlas stack's own)
python -m strix.integrations.atlas.worker --runner cli          # real scans
python -m strix.integrations.atlas.worker --runner stub --once  # no Docker/LLM
```

`--runner cli` launches `python -m strix -n -t <pinned-url> --scan-mode <mode>
--max-budget <budget>` per task and needs Docker plus a working LLM route -
the same requirements as a manual headless Strix run. `--runner stub` writes
representative artifacts through the fork's own report writer
(`strix.report.writer`) so the harvest/Atlas-ingestion path is exercised end
to end without Docker or an LLM. Stub output is always labeled
`runner="stub"` / `source="strix-stub-representative"` and never claims to be
a scan.

## Contract v1.2 (Asset Atlas side)

Task subject `atlas.task.strix_scan` with payload
`{"run_id": str, "profile": <registry key>, "target": <loopback URL>}`.
Events published: `strix.run_started`, `strix.run_completed`,
`strix.run_rejected` (invalid tasks), and one `strix.finding` per finding
(`hypothesis: true`, `check_class: "agentic"`, `evidence_run_uid` audit link).
Findings are raw observations, NOT `report.candidate`: that contract expects
SQLite evidence ids that only exist after the recorder assigns them, so
Atlas-side candidate generation owns the `strix.finding` -> `report.candidate`
step (contract v1.2 proposal).
Findings reuse the probe worker's asset key
(`local-http-<port>.loopback.fixture`) so they land on the same asset
timeline.
