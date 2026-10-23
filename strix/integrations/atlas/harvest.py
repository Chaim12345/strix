"""Harvest a finished Strix run directory into Asset Atlas event envelopes.

Reads the real artifacts Strix writes (run.json + vulnerabilities.json) and
maps every finding to a raw strix.finding event with hypothesis=True.
Findings deliberately do NOT use report.candidate: that contract expects
evidence_event_ids as SQLite log row ids, which only exist after the Atlas
recorder assigns them - a bus worker cannot know them. Atlas-side candidate
generation (Lane D) turns strix.finding into report.candidate with real
evidence ids. Envelope shape matches asset_atlas.bus.make_event:
{"uid", "type", "asset_key", "payload", "ts"}.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")


def make_envelope(
    type_: str, asset_key: str, payload: dict[str, Any], ts: float | None = None
) -> dict[str, Any]:
    return {
        "uid": uuid.uuid4().hex,
        "type": type_,
        "asset_key": asset_key,
        "payload": payload,
        "ts": ts if ts is not None else time.time(),
    }


def asset_key_for_target(port: int) -> str:
    """Match the Atlas probe worker's key so findings land on the same asset timeline."""
    return f"local-http-{port}.loopback.fixture"


def _norm_severity(value: Any) -> str:
    sev = str(value or "info").strip().lower()
    return sev if sev in SEVERITIES else "info"


def _finding_fingerprint(asset_key: str, title: str) -> str:
    """Stable dedup fingerprint: same finding on the same asset across runs.

    Run-scoped ids (strix_finding_id, run ids) change every scan; this does
    not, so Atlas-side dedup (fingerprint | id | asset+title hash) collapses
    repeats of the same hypothesis.
    """
    return hashlib.sha1(
        f"{asset_key}|{title.strip().lower()}".encode(), usedforsecurity=False
    ).hexdigest()[:12]


def load_run_artifacts(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run_record_path = run_dir / "run.json"
    if not run_record_path.is_file():
        raise FileNotFoundError(f"no run.json in {run_dir}")
    run_record = json.loads(run_record_path.read_text(encoding="utf-8"))
    vulns_path = run_dir / "vulnerabilities.json"
    vulns: list[dict[str, Any]] = []
    if vulns_path.is_file():
        data = json.loads(vulns_path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"vulnerabilities.json in {run_dir} is not a list")
        vulns = [v for v in data if isinstance(v, dict)]
    return run_record, vulns


def harvest_run(
    run_dir: Path,
    *,
    run_id: str,
    profile: str,
    target: str,
    asset_key: str,
    runner: str,
    exit_code: int,
    duration_s: float,
    source_label: str,
    fixture_id: str | None = None,
) -> list[dict[str, Any]]:
    """Build the event sequence for one finished run.

    Order: strix.run_completed first, then one strix.finding per finding,
    each carrying evidence_run_uid=<run_completed uid>.
    """
    run_record, vulns = load_run_artifacts(run_dir)

    completed = make_envelope(
        "strix.run_completed",
        asset_key,
        {
            "run_id": run_id,
            "profile": profile,
            "target": target,
            "runner": runner,
            "exit_code": exit_code,
            "status": str(run_record.get("status") or "unknown"),
            "vuln_count": len(vulns),
            "duration_s": round(duration_s, 3),
            "run_dir": str(run_dir),
            "fixture_id": fixture_id,
        },
    )
    events = [completed]
    for vuln in vulns:
        finding_id = str(vuln.get("id") or uuid.uuid4().hex)
        title = str(vuln.get("title") or "strix finding")
        events.append(
            make_envelope(
                "strix.finding",
                asset_key,
                {
                    "title": title,
                    "fingerprint": _finding_fingerprint(asset_key, title),
                    "hypothesis": True,
                    "source": source_label,
                    "check_class": "agentic",
                    "severity": _norm_severity(vuln.get("severity")),
                    "strix_run_id": run_id,
                    "strix_finding_id": finding_id,
                    "target": str(vuln.get("target") or target),
                    # audit link to the run envelope's uid (NOT a SQLite
                    # evidence id; see module docstring)
                    "evidence_run_uid": completed["uid"],
                },
            )
        )
    return events
