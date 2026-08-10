"""
forge/providers/cli.py - ``forge-detect`` CLI for backend introspection.

Run via:
    python -m forge.providers

Prints the resolved planner + executor chains, plus skipped probes and a
hint to enable paid backends if the user wants more options.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from forge.providers.discovery import discover_backends
from forge.providers.router import build_router_from_discovery


async def _async_main(args: argparse.Namespace) -> int:
    result = await discover_backends(probe_timeout_s=args.probe_timeout)

    print(
        f"Discovery: ran {len(result.backends) + len(result.skipped)} probes "
        f"in {result.duration_s:.2f}s"
    )
    print(
        f"Paid backends allowed: {result.paid_allowed}  (set FORGE_ALLOW_PAID_BACKENDS=1 to opt in)"
    )
    print()

    if not result.backends:
        print("No backends detected. Configure FORGE_LLM_MODEL_PATH to point at a")
        print("GGUF file, OR start Ollama (port 11434), OR set an API key.")
        return 1

    print(f"Detected {len(result.backends)} backends (in default order):")
    for b in result.backends:
        backstop = " (BACKSTOP)" if b.backend_name == "llama_cpp" else ""
        print(f"  - {b.backend_name:22s} family={b.family:18s} model={b.model_id[:60]}{backstop}")
        print(
            f"    {' ':22s}tier={[t.value for t in b.tier_assignment.tiers]} "
            f"primary={b.tier_assignment.primary_tier.value} "
            f"endpoint={b.endpoint or '(in-process)'}"
        )

    if args.build_chains:
        print()
        try:
            router = build_router_from_discovery(result)
        except ValueError as exc:
            print(f"Could not build router: {exc}", file=sys.stderr)
            return 2
        print(router.chain_summary)

    if result.skipped:
        print()
        print(f"Skipped probes ({len(result.skipped)}):")
        for name, reason in result.skipped:
            print(f"  - {name:22s} ({reason})")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="forge-detect",
        description=(
            "Probe the local machine for usable LLM backends and print the "
            "tier-classified chain that the forge router would use."
        ),
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=3.0,
        help="Per-probe timeout in seconds (default: 3.0).",
    )
    parser.add_argument(
        "--build-chains",
        action="store_true",
        default=True,
        help="Also build and print the resolved planner / executor chains.",
    )
    args = parser.parse_args(argv)
    return asyncio.run(_async_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
