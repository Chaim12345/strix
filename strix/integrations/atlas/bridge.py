"""NATS bridge worker: consumes atlas.task.strix_scan, runs scans, publishes events.

Asset Atlas owns orchestration (planner -> bus -> worker -> recorder ->
projections). This worker is the Strix-side half of the boundary: it consumes
scan tasks from the Atlas JetStream stream, executes the scan with the
selected runner, and publishes strix.run_started / strix.run_completed /
report.candidate events back onto atlas.event.*. It never writes to the Atlas
SQLite log - the recorder is the only log writer.
"""

from __future__ import annotations

import contextlib
import json
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from .guard import assert_loopback_url, preflight_target
from .harvest import asset_key_for_target, harvest_run, make_envelope
from .registry import validate_task
from .runner import select_runner


TASK_SUBJECT = "atlas.task.strix_scan"
EVENT_PREFIX = "atlas.event."
DURABLE = "worker-strix"


async def _publish(js: Any, envelope: dict[str, Any]) -> None:
    await js.publish(EVENT_PREFIX + envelope["type"], json.dumps(envelope).encode())


async def handle_task(
    task: dict[str, Any], js: Any, runner_name: str, workdir: Path
) -> list[dict[str, Any]]:
    """Process one atlas.task.strix_scan payload. Returns published envelopes.

    Invalid tasks produce a strix.run_rejected event (never a crash-loop:
    the message is acked after the rejection event is published).
    """
    published: list[dict[str, Any]] = []
    run_id = str(task.get("run_id") or f"unknown-{uuid.uuid4().hex[:8]}")
    try:
        config = validate_task(task)
        pinned_url, _host, port = assert_loopback_url(config["target"])
        config["target"] = pinned_url
        preflight_target(pinned_url)
    except ValueError as exc:
        rejection = make_envelope(
            "strix.run_rejected",
            "strix-scan.loopback.fixture",
            {
                "run_id": run_id,
                "reason": str(exc),
                "raw_target": str(task.get("target")),
                "fixture_id": task.get("fixture_id"),
            },
        )
        await _publish(js, rejection)
        return [rejection]

    asset_key = asset_key_for_target(port)
    runner = select_runner(runner_name)

    started = make_envelope(
        "strix.run_started",
        asset_key,
        {
            "run_id": config["run_id"],
            "profile": config["profile"],
            "target": config["target"],
            "runner": runner.name,
            "fixture_id": config.get("fixture_id"),
        },
    )
    await _publish(js, started)
    published.append(started)

    t0 = time.monotonic()
    outcome = runner.run(config, workdir)
    duration = time.monotonic() - t0

    events = harvest_run(
        outcome.run_dir,
        run_id=config["run_id"],
        profile=config["profile"],
        target=config["target"],
        asset_key=asset_key,
        runner=outcome.runner,
        exit_code=outcome.exit_code,
        duration_s=duration,
        source_label=outcome.source_label,
        fixture_id=config.get("fixture_id"),
    )
    for envelope in events:
        await _publish(js, envelope)
        published.append(envelope)
    return published


async def consume(
    nats_url: str = "nats://127.0.0.1:4222",
    runner_name: str = "cli",
    workdir: Path | None = None,
    once: bool = False,
    max_batch: int = 1,
) -> int:
    """Durable pull consumption of atlas.task.strix_scan. Returns tasks handled."""
    import nats
    import nats.errors
    from nats.js.api import ConsumerConfig

    nc = await nats.connect(nats_url, connect_timeout=5)
    js = nc.jetstream()
    handled = 0
    try:
        with contextlib.suppress(Exception):
            # consumer may already exist from a previous run
            await js.add_consumer(
                "ATLAS",
                ConsumerConfig(durable_name=DURABLE, max_deliver=5, filter_subject=TASK_SUBJECT),
            )
        sub = await js.pull_subscribe(TASK_SUBJECT, durable=DURABLE, stream="ATLAS")
        while True:
            try:
                msgs = await sub.fetch(max_batch, timeout=3)
            except nats.errors.TimeoutError:
                msgs = []
            if not msgs:
                if once:
                    break
                continue
            for msg in msgs:
                task = json.loads(msg.data.decode())
                run_id_safe = str(task.get("run_id") or "run").replace("/", "_")
                ctx = (
                    tempfile.TemporaryDirectory(prefix=f"atlas-strix-{run_id_safe}-")
                    if workdir is None
                    else _NullCtx(workdir)
                )
                with ctx as wd:
                    await handle_task(task, js, runner_name, Path(wd))
                await msg.ack()
                handled += 1
    finally:
        await nc.close()
    return handled


class _NullCtx:
    def __init__(self, value: Path) -> None:
        self.value = value

    def __enter__(self) -> Path:
        return self.value

    def __exit__(self, *exc: object) -> None:
        return None
