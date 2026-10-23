"""Registry + loopback guard tests for the Atlas bridge."""

from __future__ import annotations

import pytest

from strix.integrations.atlas.guard import assert_loopback, assert_loopback_url
from strix.integrations.atlas.registry import SCAN_PROFILES, validate_task


def _task(**over):
    task = {"run_id": "run-1", "profile": "web-fixture-quick", "target": "http://127.0.0.1:8899/"}
    task.update(over)
    return task


class TestRegistry:
    def test_valid_task_normalizes(self):
        cfg = validate_task(_task())
        assert cfg["run_id"] == "run-1"
        assert cfg["scan_mode"] == SCAN_PROFILES["web-fixture-quick"]["scan_mode"]
        assert cfg["max_budget"] == SCAN_PROFILES["web-fixture-quick"]["max_budget"]

    def test_all_registry_profiles_valid(self):
        for name in SCAN_PROFILES:
            cfg = validate_task(_task(profile=name))
            assert cfg["profile"] == name

    def test_unknown_profile_rejected(self):
        with pytest.raises(ValueError, match="unknown scan profile"):
            validate_task(_task(profile="deep-everything"))

    def test_raw_flags_rejected(self):
        with pytest.raises(ValueError, match="unexpected task keys"):
            validate_task(_task(scan_mode="deep"))
        with pytest.raises(ValueError, match="unexpected task keys"):
            validate_task(_task(extra_flag="--no-sandbox"))

    def test_bad_run_id_rejected(self):
        for bad in ("", "  ", "a/b", "a\\b", "..", 123):
            with pytest.raises(ValueError):
                validate_task(_task(run_id=bad))

    def test_missing_target_rejected(self):
        with pytest.raises(ValueError):
            validate_task(_task(target=""))


class TestGuard:
    def test_loopback_literal_accepted(self):
        assert assert_loopback("127.0.0.1") == "127.0.0.1"
        assert assert_loopback("127.0.1.5").startswith("127.")

    def test_public_ip_rejected(self):
        with pytest.raises(ValueError, match="not loopback"):
            assert_loopback("8.8.8.8")

    def test_url_pinned_to_literal(self):
        pinned, host, port = assert_loopback_url("http://localhost:8899/app")
        assert host == "localhost"
        assert port == 8899
        assert pinned.startswith("http://127.")
        assert ":8899/app" in pinned

    def test_public_url_rejected(self):
        with pytest.raises(ValueError, match="not loopback"):
            assert_loopback_url("http://169.254.169.254/latest/meta-data")

    def test_scheme_and_creds_rejected(self):
        with pytest.raises(ValueError, match="scheme"):
            assert_loopback_url("ftp://127.0.0.1:21/")
        with pytest.raises(ValueError, match="credentials"):
            assert_loopback_url("http://user:pw@127.0.0.1:8899/")
