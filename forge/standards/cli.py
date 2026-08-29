from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.standards.vulnerabilities import (
    enrich_vulnerability_findings,
    vulnerability_stix_bundle,
    vulnerability_stix_enrichment_preview,
    vulnerability_taxii_manifest,
)

console = Console(stderr=True)


def register_standards_commands(app: typer.Typer) -> None:
    @app.command("export-stix")
    def export_stix(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        bundle_file: Path | None = typer.Option(
            None,
            "--bundle-file",
            dir_okay=False,
            writable=True,
            help="Write the STIX 2.1 bundle JSON to this file. Defaults to stdout.",
        ),
        taxii_manifest_file: Path | None = typer.Option(
            None,
            "--taxii-manifest-file",
            dir_okay=False,
            writable=True,
            help="Write a TAXII-style collection manifest JSON beside the bundle.",
        ),
        title: str = typer.Option(
            "Forge Vulnerability Standards Export",
            "--title",
            help="Title stored in the STIX bundle x_forge_export block.",
        ),
        collection_id: str = typer.Option(
            "forge-vulnerability-standards",
            "--collection-id",
            help="Collection ID stored in the TAXII-style manifest.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Export normalized vulnerability findings as local STIX/TAXII JSON."""
        try:
            con = _open_standards_db(engagement)
            try:
                rows = _load_vulnerability_rows(con, engagement)
                stix_bundle = vulnerability_stix_bundle(rows, title=title)
                taxii_manifest = vulnerability_taxii_manifest(
                    stix_bundle,
                    collection_id=collection_id,
                )
            finally:
                con.close()
            if bundle_file is not None:
                _write_json_file(bundle_file, stix_bundle)
            if taxii_manifest_file is not None:
                _write_json_file(taxii_manifest_file, taxii_manifest)
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc

        result = {
            "schema_version": "forge.standards.stix_export.v1",
            "engagement_id": int(engagement),
            "status": "exported",
            "source": "vulnerability_findings",
            "bundle_file": str(bundle_file) if bundle_file is not None else "",
            "taxii_manifest_file": (
                str(taxii_manifest_file) if taxii_manifest_file is not None else ""
            ),
            "finding_count": len(rows),
            "object_count": len(stix_bundle.get("objects", [])),
            "total_count": len(rows),
            "selected_count": len(stix_bundle.get("objects", [])),
            "omitted_count": max(0, len(rows) - len(stix_bundle.get("objects", []))),
            "media_type": "application/stix+json;version=2.1",
            "network_calls": False,
            "execution_policy": "local_only; exports stored reportable metadata only",
        }
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        if bundle_file is None:
            typer.echo(json.dumps(stix_bundle, sort_keys=True, indent=2))
            return
        console.print(
            "[bold]Local STIX export[/bold] "
            f"status=exported findings={result['finding_count']} "
            f"objects={result['object_count']} bundle={bundle_file}"
        )

    @app.command("import-stix")
    def import_stix(
        engagement: int = typer.Option(..., "--engagement", "-e"),
        bundle_file: Path = typer.Option(
            ...,
            "--bundle-file",
            exists=True,
            dir_okay=False,
            readable=True,
            help="Local STIX 2.1 bundle JSON file with vulnerability objects.",
        ),
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Preview matching CVEs without updating vulnerability findings.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Enrich existing CVE findings from a local STIX vulnerability bundle."""
        try:
            stix_bundle = _load_stix_bundle(bundle_file)
            con = _open_standards_db(engagement)
            try:
                preview = vulnerability_stix_enrichment_preview(
                    con,
                    engagement,
                    stix_bundle,
                )
                if dry_run or preview["matched_finding_count"] == 0:
                    processed = 0
                else:
                    processed = enrich_vulnerability_findings(
                        con,
                        engagement,
                        stix_bundle=stix_bundle,
                        only_stix_matches=True,
                    )
            finally:
                con.close()
        except (OSError, json.JSONDecodeError, sqlite3.Error, ValueError) as exc:
            raise typer.BadParameter(str(exc)) from exc

        status = "planned" if dry_run else "imported"
        if not dry_run and preview["matched_finding_count"] == 0:
            status = "no_matches"
        result = {
            **preview,
            "schema_version": "forge.standards.stix_import.v1",
            "status": status,
            "source": "local_stix_bundle",
            "bundle_file": str(bundle_file),
            "processed_finding_count": processed,
            "total_count": int(preview.get("stix_cve_count", 0) or 0),
            "selected_count": int(preview.get("matched_finding_count", 0) or 0),
            "omitted_count": len(preview.get("unmatched_stix_cve_ids", []) or []),
            "execution_policy": (
                "dry_run_local_stix_match_preview_no_writes"
                if dry_run
                else "local_only; CVE-matched enrichment; no new findings are created"
            ),
        }
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return

        console.print(
            "[bold]Local STIX import[/bold] "
            f"status={status} stix_cves={result['stix_cve_count']} "
            f"matched_findings={result['matched_finding_count']} "
            f"processed_findings={processed}"
        )
        if result["unmatched_stix_cve_ids"]:
            console.print(
                "[dim]Unmatched STIX CVEs: "
                + ", ".join(result["unmatched_stix_cve_ids"][:20])
                + "[/dim]"
            )


def _load_stix_bundle(path: Path) -> dict[str, Any] | list[Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, (dict, list)):
        raise ValueError("STIX bundle file must contain a JSON object or array")
    return payload


def _write_json_file(path: Path, payload: dict[str, Any] | list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _load_vulnerability_rows(
    con: sqlite3.Connection,
    engagement: int,
) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT *
        FROM vulnerability_findings
        WHERE engagement_id=?
        ORDER BY id
        """,
        (int(engagement),),
    ).fetchall()


def _open_standards_db(engagement: int) -> sqlite3.Connection:
    cfg = ForgeConfig.load()
    con = direct_connect(cfg.engagement_db_path(str(engagement)))
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con
