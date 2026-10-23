"""Harvest tests against artifacts written by the fork's OWN report writer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path

from strix.integrations.atlas.harvest import (
    asset_key_for_target,
    harvest_run,
    load_run_artifacts,
)
from strix.report.writer import write_run_record, write_vulnerabilities


def _make_real_run(run_dir: Path) -> None:
    """Produce run.json + vulnerabilities.json via the real writer code path."""
    now = datetime.now(UTC).isoformat()
    write_run_record(
        run_dir,
        {
            "run_name": run_dir.name,
            "status": "completed",
            "scan_mode": "quick",
            "started_at": now,
            "ended_at": now,
            "llm_usage": {"cost": 0.0},
        },
    )
    write_vulnerabilities(
        run_dir,
        [
            {
                "id": "VULN-AAA",
                "title": "Reflected XSS in fixture search",
                "severity": "HIGH",  # uppercase on purpose: harvest must normalize
                "timestamp": now,
                "target": "http://127.0.0.1:8899/search",
                "description": "Fixture finding A",
                "impact": "Fixture impact",
            },
            {
                "id": "VULN-BBB",
                "title": "Verbose server header",
                "severity": "low",
                "timestamp": now,
                "target": "http://127.0.0.1:8899/",
                "description": "Fixture finding B",
                "impact": "Fixture impact",
            },
        ],
        set(),
    )


class TestHarvestRealArtifacts:
    def test_load_run_artifacts_roundtrip(self, tmp_path):
        run_dir = tmp_path / "strix_runs" / "run-x"
        run_dir.mkdir(parents=True)
        _make_real_run(run_dir)
        record, vulns = load_run_artifacts(run_dir)
        assert record["status"] == "completed"
        assert len(vulns) == 2

    def test_harvest_maps_findings_to_candidates(self, tmp_path):
        run_dir = tmp_path / "strix_runs" / "run-y"
        run_dir.mkdir(parents=True)
        _make_real_run(run_dir)
        events = harvest_run(
            run_dir,
            run_id="run-y",
            profile="web-fixture-quick",
            target="http://127.0.0.1:8899/",
            asset_key=asset_key_for_target(8899),
            runner="cli",
            exit_code=2,
            duration_s=12.5,
            source_label="strix",
        )
        assert events[0]["type"] == "strix.run_completed"
        assert events[0]["payload"]["vuln_count"] == 2
        assert events[0]["payload"]["exit_code"] == 2
        findings = events[1:]
        assert len(findings) == 2
        for env in findings:
            assert env["type"] == "strix.finding"
            p = env["payload"]
            assert p["hypothesis"] is True
            assert p["source"] == "strix"
            assert p["check_class"] == "agentic"
            # uid audit link, NOT a SQLite evidence id (those only exist
            # after the Atlas recorder assigns them)
            assert p["evidence_run_uid"] == events[0]["uid"]
            assert len(p["fingerprint"]) == 12
            assert "evidence_event_ids" not in p
            assert p["strix_run_id"] == "run-y"
            assert env["asset_key"] == "local-http-8899.loopback.fixture"
        assert findings[0]["payload"]["severity"] == "high"  # normalized from HIGH
        assert findings[0]["payload"]["strix_finding_id"] == "VULN-AAA"
        # envelope shape matches asset_atlas.bus.make_event
        for env in events:
            assert set(env) == {"uid", "type", "asset_key", "payload", "ts"}

    def test_fingerprint_stable_across_runs(self, tmp_path):
        fps = []
        for run_id in ("run-a", "run-b"):
            run_dir = tmp_path / "strix_runs" / run_id
            run_dir.mkdir(parents=True)
            _make_real_run(run_dir)
            events = harvest_run(
                run_dir,
                run_id=run_id,
                profile="web-fixture-quick",
                target="http://127.0.0.1:8899/",
                asset_key="local-http-8899.loopback.fixture",
                runner="cli",
                exit_code=2,
                duration_s=1.0,
                source_label="strix",
            )
            fps.append([e["payload"]["fingerprint"] for e in events[1:]])
        assert fps[0] == fps[1]
        assert fps[0][0] != fps[0][1]  # different findings differ

    def test_empty_vulns_still_completes(self, tmp_path):
        run_dir = tmp_path / "strix_runs" / "run-z"
        run_dir.mkdir(parents=True)
        _make_real_run(run_dir)
        (run_dir / "vulnerabilities.json").write_text("[]", encoding="utf-8")
        events = harvest_run(
            run_dir,
            run_id="run-z",
            profile="web-fixture-quick",
            target="http://127.0.0.1:8899/",
            asset_key="local-http-8899.loopback.fixture",
            runner="cli",
            exit_code=0,
            duration_s=1.0,
            source_label="strix",
        )
        assert len(events) == 1
        assert events[0]["payload"]["vuln_count"] == 0
