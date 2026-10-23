"""Scan launch strategies for the Atlas bridge.

CLIRunner is the real path: it shells out to the Strix headless CLI
(strix -n -t <target> --scan-mode ... --max-budget ...) and requires Docker
plus a working LLM route, exactly like a manual Strix run. If those are
missing it fails loudly - nothing is faked.

LLM access is endpoint-abstracted (the fork already supports this natively):
STRIX_LLM picks the model id, LLM_API_KEY the credential, and LLM_API_BASE
points at any OpenAI-compatible endpoint - including a local/self-hosted
model on this machine, which needs no external account at all. The bridge
reads LLM config from the OPERATOR's environment, never from the bus, and
refuses remote LLM endpoints unless explicitly opted in
(ATLAS_STRIX_ALLOW_REMOTE_LLM=1).

StubRunner exists so the orchestration boundary (task in -> events out) can be
exercised without Docker/LLM. It writes representative artifacts THROUGH THE
FORK'S OWN report writer (strix.report.writer), so everything downstream of
the scan itself (harvest, event mapping, Atlas ingestion) runs the real code
path. Every event it produces is labeled runner="stub" and
source="strix-stub-representative". It never claims to be a scan.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse


if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class RunOutcome:
    exit_code: int
    run_dir: Path
    duration_s: float
    runner: str
    source_label: str


@dataclass
class LLMConfig:
    """Operator-supplied LLM route for scan subprocesses. Never from the bus."""

    model: str | None
    api_key: str | None
    api_base: str | None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LLMConfig:
        env = os.environ if env is None else env
        return cls(
            model=env.get("STRIX_LLM") or None,
            api_key=env.get("LLM_API_KEY") or None,
            api_base=env.get("LLM_API_BASE") or None,
        )

    def validate(self, env: dict[str, str] | None = None) -> None:
        env = os.environ if env is None else env
        if not self.model:
            raise RuntimeError(
                "no LLM configured for strix_scan: set STRIX_LLM + LLM_API_KEY, or point "
                "LLM_API_BASE at a local OpenAI-compatible model (no external account "
                "needed), or use --runner stub. Nothing is faked."
            )
        if self.api_base:
            parsed = urlparse(self.api_base)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise RuntimeError(f"LLM_API_BASE {self.api_base!r} is not a valid http(s) URL")
            host = parsed.hostname
            is_loopback = host == "localhost" or host.startswith("127.") or host == "::1"
            if not is_loopback and env.get("ATLAS_STRIX_ALLOW_REMOTE_LLM") != "1":
                raise RuntimeError(
                    f"LLM_API_BASE host {host!r} is not loopback; set "
                    "ATLAS_STRIX_ALLOW_REMOTE_LLM=1 to opt into a remote endpoint"
                )

    def subprocess_env(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.model:
            out["STRIX_LLM"] = self.model
        if self.api_key:
            out["LLM_API_KEY"] = self.api_key
        if self.api_base:
            out["LLM_API_BASE"] = self.api_base
        return out


def _runs_base(workdir: Path) -> Path:
    return workdir / "strix_runs"


class CLIRunner:
    """Real headless Strix scan. Requires Docker running + a working LLM route."""

    name = "cli"
    source_label = "strix"

    def __init__(self, llm: LLMConfig | None = None) -> None:
        self.llm = llm or LLMConfig.from_env()

    def run(self, config: dict[str, Any], workdir: Path) -> RunOutcome:
        self.llm.validate()
        base = _runs_base(workdir)
        before = {p.name for p in base.iterdir()} if base.is_dir() else set()
        cmd = [
            sys.executable,
            "-m",
            "strix",
            "-n",
            "-t",
            config["target"],
            "--scan-mode",
            config["scan_mode"],
            "--max-budget",
            f"{config['max_budget']:.2f}",
        ]
        env = dict(os.environ)
        env.update(self.llm.subprocess_env())
        started = time.monotonic()
        proc = subprocess.run(  # noqa: S603 - argv built from validated registry config; shell=False
            cmd, check=False, cwd=workdir, env=env, capture_output=True, text=True, timeout=6 * 3600
        )
        duration = time.monotonic() - started
        after = {p.name for p in base.iterdir()} if base.is_dir() else set()
        new_dirs = sorted(after - before)
        if not new_dirs:
            raise RuntimeError(
                "strix CLI exited "
                f"{proc.returncode} but produced no run directory. "
                f"stderr tail: {(proc.stderr or '')[-500:]}"
            )
        return RunOutcome(
            exit_code=proc.returncode,
            run_dir=base / new_dirs[-1],
            duration_s=duration,
            runner=self.name,
            source_label=self.source_label,
        )


class StubRunner:
    """Representative-artifact runner for environments without Docker/LLM.

    NOT A SCAN. Writes one fixed representative finding via the fork's own
    report writer so the harvest/ingest path is exercised end to end.
    """

    name = "stub"
    source_label = "strix-stub-representative"

    def run(self, config: dict[str, Any], workdir: Path) -> RunOutcome:
        from strix.report.writer import write_run_record, write_vulnerabilities

        started = time.monotonic()
        run_dir = _runs_base(workdir) / f"atlas-stub-{config['run_id']}"
        run_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(UTC).isoformat()
        write_run_record(
            run_dir,
            {
                "run_name": run_dir.name,
                "status": "completed",
                "scan_mode": config["scan_mode"],
                "targets": [{"type": "url", "details": {"target_url": config["target"]}}],
                "started_at": now,
                "ended_at": now,
                "llm_usage": {"cost": 0.0},
                "notes": "STUB RUNNER - representative artifact, not a real scan",
            },
        )
        write_vulnerabilities(
            run_dir,
            [
                {
                    "id": f"STUB-{config['run_id'][:8]}",
                    "title": "Representative stub finding (no scan performed)",
                    "severity": "info",
                    "timestamp": now,
                    "target": config["target"],
                    "description": (
                        "Produced by the Atlas bridge StubRunner through the "
                        "fork's real report writer. Exercises the harvest and "
                        "Atlas ingestion path only."
                    ),
                    "impact": "None - synthetic representative artifact.",
                    "poc_description": "N/A (stub)",
                }
            ],
            set(),
        )
        return RunOutcome(
            exit_code=0,
            run_dir=run_dir,
            duration_s=time.monotonic() - started,
            runner=self.name,
            source_label=self.source_label,
        )


def select_runner(name: str) -> CLIRunner | StubRunner:
    if name == "cli":
        return CLIRunner()
    if name == "stub":
        return StubRunner()
    raise ValueError(f"unknown runner {name!r} (expected 'cli' or 'stub')")
