"""Bridge orchestration tests: task in -> runner -> published event sequence."""

from __future__ import annotations

import asyncio
import http.server
import json
import threading

import pytest

from strix.integrations.atlas.bridge import handle_task
from strix.integrations.atlas.runner import LLMConfig, StubRunner


@pytest.fixture()
def fixture_server():
    """Real loopback HTTP fixture so the bridge pre-flight sees a live target."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    server.server_close()


class FakeJS:
    """Stands in for a JetStream context: records (subject, payload) publishes."""

    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    async def publish(self, subject: str, data: bytes):
        self.published.append((subject, json.loads(data.decode())))


class TestHandleTaskStubRunner:
    def test_full_sequence(self, tmp_path, fixture_server):
        js = FakeJS()
        task = {
            "run_id": "demo-1",
            "profile": "web-fixture-quick",
            "target": f"http://127.0.0.1:{fixture_server}/",
        }
        published = asyncio.run(handle_task(task, js, "stub", tmp_path))
        types = [e["type"] for e in published]
        assert types == ["strix.run_started", "strix.run_completed", "strix.finding"]
        # subjects onto the bus carry the atlas.event. prefix
        subjects = [s for s, _ in js.published]
        assert subjects == [
            "atlas.event.strix.run_started",
            "atlas.event.strix.run_completed",
            "atlas.event.strix.finding",
        ]
        finding = published[-1]["payload"]
        assert finding["hypothesis"] is True
        assert finding["source"] == "strix-stub-representative"  # honest stub label
        assert finding["evidence_run_uid"] == published[1]["uid"]
        assert published[0]["payload"]["runner"] == "stub"
        assert published[-1]["asset_key"] == f"local-http-{fixture_server}.loopback.fixture"

    def test_rejection_for_public_target(self, tmp_path):
        js = FakeJS()
        task = {"run_id": "evil-1", "profile": "web-fixture-quick", "target": "http://8.8.8.8/"}
        published = asyncio.run(handle_task(task, js, "stub", tmp_path))
        assert [e["type"] for e in published] == ["strix.run_rejected"]
        assert "not loopback" in published[0]["payload"]["reason"]

    def test_rejection_for_unknown_profile(self, tmp_path):
        js = FakeJS()
        task = {"run_id": "evil-2", "profile": "nuclear", "target": "http://127.0.0.1:8899/"}
        published = asyncio.run(handle_task(task, js, "stub", tmp_path))
        assert published[0]["type"] == "strix.run_rejected"
        assert "unknown scan profile" in published[0]["payload"]["reason"]

    def test_rejection_for_raw_flags(self, tmp_path):
        js = FakeJS()
        task = {
            "run_id": "evil-3",
            "profile": "web-fixture-quick",
            "target": "http://127.0.0.1:8899/",
            "max_budget": 9999,
        }
        published = asyncio.run(handle_task(task, js, "stub", tmp_path))
        assert published[0]["type"] == "strix.run_rejected"
        assert "unexpected task keys" in published[0]["payload"]["reason"]

    def test_rejection_for_dead_fixture(self, tmp_path):
        # nothing listens on 8999: pre-flight must reject before any "scan"
        js = FakeJS()
        task = {
            "run_id": "dead-1",
            "profile": "web-fixture-quick",
            "target": "http://127.0.0.1:8999/",
        }
        published = asyncio.run(handle_task(task, js, "stub", tmp_path))
        assert [e["type"] for e in published] == ["strix.run_rejected"]
        assert "unreachable" in published[0]["payload"]["reason"]

    def test_fixture_id_accepted_and_echoed(self, tmp_path, fixture_server):
        js = FakeJS()
        task = {
            "run_id": "fx-1",
            "profile": "web-fixture-quick",
            "target": f"http://127.0.0.1:{fixture_server}/",
            "fixture_id": "web-fixture",
        }
        published = asyncio.run(handle_task(task, js, "stub", tmp_path))
        assert published[0]["payload"]["fixture_id"] == "web-fixture"
        assert published[1]["payload"]["fixture_id"] == "web-fixture"

    def test_bad_fixture_id_rejected(self, tmp_path):
        js = FakeJS()
        task = {
            "run_id": "fx-2",
            "profile": "web-fixture-quick",
            "target": "http://127.0.0.1:8899/",
            "fixture_id": "../escape",
        }
        published = asyncio.run(handle_task(task, js, "stub", tmp_path))
        assert published[0]["type"] == "strix.run_rejected"
        assert "fixture_id" in published[0]["payload"]["reason"]


class TestLLMConfig:
    def test_missing_model_fails_loudly(self):
        cfg = LLMConfig(model=None, api_key=None, api_base=None)
        with pytest.raises(RuntimeError, match="no LLM configured"):
            cfg.validate(env={})

    def test_loopback_base_ok_without_key(self):
        cfg = LLMConfig(
            model="openai/local-model", api_key=None, api_base="http://127.0.0.1:8401/v1"
        )
        cfg.validate(env={})
        assert cfg.subprocess_env()["LLM_API_BASE"] == "http://127.0.0.1:8401/v1"

    def test_remote_base_needs_opt_in(self):
        cfg = LLMConfig(model="openai/x", api_key="k", api_base="https://api.example.com/v1")
        with pytest.raises(RuntimeError, match="not loopback"):
            cfg.validate(env={})
        cfg.validate(env={"ATLAS_STRIX_ALLOW_REMOTE_LLM": "1"})  # opt-in passes

    def test_subprocess_env_passthrough(self):
        cfg = LLMConfig(model="openai/m", api_key="k", api_base=None)
        env = cfg.subprocess_env()
        assert env == {"STRIX_LLM": "openai/m", "LLM_API_KEY": "k"}


class TestStubRunnerHonesty:
    def test_stub_marks_itself(self, tmp_path):
        outcome = StubRunner().run(
            {
                "run_id": "honesty-1",
                "profile": "web-fixture-quick",
                "target": "http://127.0.0.1:8899/",
                "scan_mode": "quick",
                "max_budget": 5.0,
            },
            tmp_path,
        )
        assert outcome.runner == "stub"
        assert outcome.source_label == "strix-stub-representative"
        record = json.loads((outcome.run_dir / "run.json").read_text())
        assert "STUB" in record["notes"]
