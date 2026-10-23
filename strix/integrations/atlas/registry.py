"""Fixed scan-profile registry for atlas.task.strix_scan payloads.

The bus carries a registry KEY only - never raw Strix CLI flags. Unknown
profile IDs are rejected. Budgets/modes are pinned here so a task message
cannot widen cost or scope.
"""

from __future__ import annotations

from typing import Any


SCAN_PROFILES: dict[str, dict[str, Any]] = {
    # Cheap smoke scan of a controlled loopback web fixture.
    "web-fixture-quick": {"scan_mode": "quick", "max_budget": 5.0},
    # Standard scan of a controlled loopback web fixture.
    "web-fixture-standard": {"scan_mode": "standard", "max_budget": 10.0},
}

ALLOWED_TASK_KEYS = frozenset({"run_id", "profile", "target", "fixture_id"})

VALID_SCAN_MODES = frozenset({"quick", "standard", "deep"})


def validate_task(task: dict[str, Any]) -> dict[str, Any]:
    """Normalize an atlas.task.strix_scan payload or raise ValueError.

    Returns {"run_id", "profile", "target", "scan_mode", "max_budget"}.
    """
    unknown = set(task) - ALLOWED_TASK_KEYS
    if unknown:
        raise ValueError(f"atlas bridge: unexpected task keys {sorted(unknown)}")
    run_id = task.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("atlas bridge: run_id must be a non-empty string")
    if any(c in run_id for c in ("/", "\\", "..", "\x00")):
        raise ValueError("atlas bridge: run_id contains path characters")
    profile = task.get("profile")
    if profile not in SCAN_PROFILES:
        raise ValueError(
            f"atlas bridge: unknown scan profile {profile!r} (known: {sorted(SCAN_PROFILES)})"
        )
    target = task.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("atlas bridge: target must be a non-empty URL string")
    fixture_id = task.get("fixture_id")
    if fixture_id is not None:
        if not isinstance(fixture_id, str) or not fixture_id.strip():
            raise ValueError("atlas bridge: fixture_id must be a non-empty string when present")
        if any(c in fixture_id for c in ("/", "\\", "..", "\x00")):
            raise ValueError("atlas bridge: fixture_id contains path characters")
    spec = SCAN_PROFILES[profile]
    if spec["scan_mode"] not in VALID_SCAN_MODES:
        raise ValueError(f"atlas bridge: registry profile {profile!r} misconfigured")
    return {
        "run_id": run_id.strip(),
        "profile": profile,
        "target": target.strip(),
        "fixture_id": fixture_id.strip() if isinstance(fixture_id, str) else None,
        "scan_mode": spec["scan_mode"],
        "max_budget": float(spec["max_budget"]),
    }
