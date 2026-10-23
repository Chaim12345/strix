"""CLI entry: python -m strix.integrations.atlas.worker [--runner cli|stub] [--once]."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .bridge import consume


def main() -> None:
    parser = argparse.ArgumentParser(description="Asset Atlas -> Strix bridge worker")
    parser.add_argument("--nats-url", default="nats://127.0.0.1:4222")
    parser.add_argument(
        "--runner",
        choices=["cli", "stub"],
        default="cli",
        help=(
            "cli = real headless Strix scan (needs Docker + LLM route: STRIX_LLM/"
            "LLM_API_KEY or local LLM_API_BASE). stub = representative artifacts via "
            "the fork's own report writer; NOT a scan; every event labeled."
        ),
    )
    parser.add_argument(
        "--workdir", default=None, help="run working dir (default: per-task temp dir)"
    )
    parser.add_argument("--once", action="store_true", help="exit when no tasks are pending")
    args = parser.parse_args()
    asyncio.run(
        consume(
            nats_url=args.nats_url,
            runner_name=args.runner,
            workdir=Path(args.workdir) if args.workdir else None,
            once=args.once,
        )
    )


if __name__ == "__main__":
    main()
