"""Asset Atlas <-> Strix integration bridge.

Asset Atlas (local recon/discovery system) owns orchestration: it dispatches
scan tasks on its NATS JetStream backbone (atlas.task.strix_scan), and this
package is the Strix-side worker that consumes those tasks, runs a headless
Strix scan against the *controlled loopback fixture* named in the task, and
publishes the results back as atlas.event.* observations (status events plus
report.candidate findings, always hypothesis=True).

Hard rules (mirrors Asset Atlas CONTRACT.md):
- Loopback-only targets. Any non-loopback resolution raises before launch.
- Scan profiles come from a fixed registry. No raw Strix flags from the bus.
- Findings are hypotheses, never verified vulnerabilities.
- This worker never writes to the Atlas SQLite log; it only publishes events
  (the Atlas recorder is the sole log writer).
"""
