"""Typer CLI wiring for ``forge connect`` / ``forge scope`` and
``forge targets add``.

These commands keep the operator in the shell. No JSON editing is
required for the common onboarding flows:

- ``forge connect github --token-env FORGE_GITHUB_TOKEN --org myorg``
- ``forge connect list --json``
- ``forge connect remove github``
- ``forge targets add example.com``
- ``forge scope show --json``
- ``forge scope add-domain example.com``
- ``forge scope auto-expand --json`` / ``forge scope auto-expand --apply``

Credential values never travel on the command line — the only accepted
patterns are ``--token-env ENV_VAR`` and ``--token-stdin`` (or
``--key-env`` / ``--key-stdin`` for the Shodan-style key fields). This
is the explicit anti-shell-history policy documented in
:mod:`forge.onboard.service_connections`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from forge.config import ForgeConfig
from forge.onboard.auto_scope import (
    expand_scope_from_feeds,
    load_scope_manifest,
    normalize_candidate,
    write_scope_manifest,
)
from forge.onboard.github_spider import (
    GitHubSpiderError,
    spider_github,
)
from forge.onboard.service_connections import (
    ConnectionError,
    ServiceConnectionManager,
    SUPPORTED_SERVICES,
    read_env_credential,
    read_stdin_credential,
)
from forge.onboard.target_wizard import add_target


console = Console(stderr=True)


# ----------------------------------------------------------------------
# forge connect
# ----------------------------------------------------------------------


def register_connect_commands(app: typer.Typer) -> None:
    """Register the ``forge connect`` sub-commands on ``app``.

    Each service subcommand exposes only the flags relevant to that
    service — GitHub-specific flags do not appear on ``shodan`` help,
    Supabase-specific flags do not appear on ``github`` help, and so
    on. See :func:`_register_service_add_command` for the per-service
    registration.
    """

    @app.command("list")
    def connect_list(
        json_output: bool = typer.Option(
            False, "--json", help="Emit machine-readable JSON."
        ),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            envvar="FORGE_DATA_DIR",
            help="FORGE data dir. Defaults to ForgeConfig resolution.",
        ),
    ) -> None:
        """List stored service connections (credentials redacted in output)."""
        manager = _mk_manager(data_dir)
        summary = manager.to_summary(redact=True)
        if json_output:
            typer.echo(json.dumps(summary, indent=2, sort_keys=True))
            return
        _print_connection_table(summary)

    @app.command("remove")
    def connect_remove(
        service: str = typer.Argument(..., help="Service id to remove."),
        data_dir: Optional[Path] = typer.Option(
            None, "--data-dir", envvar="FORGE_DATA_DIR"
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Remove the stored connection for ``service``."""
        try:
            manager = _mk_manager(data_dir)
            removed = manager.remove_connection(service)
        except ConnectionError as exc:
            _emit_error(str(exc), json_output=json_output)
            raise typer.Exit(code=1)
        payload = {
            "service": service.strip().lower(),
            "removed": removed,
            "connections_path": str(manager.config_path),
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        if removed:
            console.print(f"[green]Removed[/green] {payload['service']} connection")
        else:
            console.print(f"[yellow]No connection[/yellow] stored for {payload['service']}")

    for service_id, descriptor in SUPPORTED_SERVICES.items():
        _register_service_add_command(app, service_id, descriptor)


def _register_service_add_command(
    app: typer.Typer,
    service_id: str,
    descriptor: dict[str, Any],
) -> None:
    """Create ``forge connect <service>`` with only the flags that service needs.

    Flag bleeding (every service showing every flag) is a known UX
    footgun — operators running ``forge connect shodan --help`` should
    not see GitHub-only ``--org`` / ``--user`` or Supabase-only
    ``--project-ref`` / ``--url``. This dispatches to a per-service
    registration function so each ``--help`` lists only its own flags.
    """
    cred_fields = tuple(descriptor["credential_fields"])
    required_fields = tuple(descriptor["required_fields"])
    optional_fields = tuple(descriptor["optional_fields"])
    help_text = descriptor.get("description", "")

    registrars: dict[str, Any] = {
        "github": _register_github_connect,
        "supabase": _register_supabase_connect,
        "shodan": _register_single_key_connect,
        "virustotal": _register_single_key_connect,
        "urlscan": _register_single_key_connect,
        "replit": _register_replit_connect,
        "censys": _register_censys_connect,
        "dehashed": _register_dehashed_connect,
    }
    registrar = registrars.get(service_id)
    if registrar is None:  # pragma: no cover - defensive guard
        raise ConnectionError(
            f"no connect-command registrar for service {service_id!r}; "
            "add a per-service registration function above"
        )
    registrar(
        app,
        service_id=service_id,
        help_text=help_text,
        cred_fields=cred_fields,
        required_fields=required_fields,
        optional_fields=optional_fields,
    )


def _register_github_connect(
    app: typer.Typer,
    *,
    service_id: str,
    help_text: str,
    cred_fields: tuple[str, ...],
    required_fields: tuple[str, ...],
    optional_fields: tuple[str, ...],
) -> None:
    """``forge connect github --token-env VAR [--org ORG] [--user USER]``."""

    @app.command(service_id, help=help_text)
    def _github_add(  # noqa: ANN202
        token_env: Optional[str] = typer.Option(
            None,
            "--token-env",
            help="Env var holding the GitHub PAT.",
        ),
        token_stdin: bool = typer.Option(
            False, "--token-stdin", help="Read GitHub PAT from stdin."
        ),
        orgs: Optional[str] = typer.Option(
            None,
            "--org",
            help="Comma-separated org slug(s) to spider.",
        ),
        users: Optional[str] = typer.Option(
            None,
            "--user",
            help="Comma-separated user slug(s) to spider.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None, "--data-dir", envvar="FORGE_DATA_DIR"
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Store the GitHub PAT and optional org/user hints."""
        _apply_service_connection(
            service_id=service_id,
            cred_fields=cred_fields,
            required=required_fields,
            optional=optional_fields,
            flag_values={
                "token_env": token_env,
                "token_stdin": token_stdin,
                "orgs": orgs,
                "users": users,
            },
            data_dir=data_dir,
            json_output=json_output,
        )


def _register_supabase_connect(
    app: typer.Typer,
    *,
    service_id: str,
    help_text: str,
    cred_fields: tuple[str, ...],
    required_fields: tuple[str, ...],
    optional_fields: tuple[str, ...],
) -> None:
    """``forge connect supabase --key-env VAR --project-ref REF [--url URL]``."""

    @app.command(service_id, help=help_text)
    def _supabase_add(  # noqa: ANN202
        key_env: Optional[str] = typer.Option(
            None,
            "--key-env",
            help="Env var holding the Supabase anon/service key.",
        ),
        key_stdin: bool = typer.Option(
            False, "--key-stdin", help="Read Supabase key from stdin."
        ),
        project_ref: Optional[str] = typer.Option(
            None, "--project-ref", help="Supabase project ref."
        ),
        supabase_url: Optional[str] = typer.Option(
            None, "--url", help="Supabase project URL (optional override)."
        ),
        data_dir: Optional[Path] = typer.Option(
            None, "--data-dir", envvar="FORGE_DATA_DIR"
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Store Supabase project ref + anon/service key."""
        _apply_service_connection(
            service_id=service_id,
            cred_fields=cred_fields,
            required=required_fields,
            optional=optional_fields,
            flag_values={
                "key_env": key_env,
                "key_stdin": key_stdin,
                "project_ref": project_ref,
                "supabase_url": supabase_url,
            },
            data_dir=data_dir,
            json_output=json_output,
        )


def _register_single_key_connect(
    app: typer.Typer,
    *,
    service_id: str,
    help_text: str,
    cred_fields: tuple[str, ...],
    required_fields: tuple[str, ...],
    optional_fields: tuple[str, ...],
) -> None:
    """``forge connect <shodan|virustotal|urlscan> --key-env VAR``."""

    @app.command(service_id, help=help_text)
    def _single_key_add(  # noqa: ANN202
        key_env: Optional[str] = typer.Option(
            None,
            "--key-env",
            help=f"Env var holding the {service_id} API key.",
        ),
        key_stdin: bool = typer.Option(
            False,
            "--key-stdin",
            help=f"Read the {service_id} API key from stdin.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None, "--data-dir", envvar="FORGE_DATA_DIR"
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Store the single-key API credential for this service."""
        _apply_service_connection(
            service_id=service_id,
            cred_fields=cred_fields,
            required=required_fields,
            optional=optional_fields,
            flag_values={
                "key_env": key_env,
                "key_stdin": key_stdin,
            },
            data_dir=data_dir,
            json_output=json_output,
        )


def _register_replit_connect(
    app: typer.Typer,
    *,
    service_id: str,
    help_text: str,
    cred_fields: tuple[str, ...],
    required_fields: tuple[str, ...],
    optional_fields: tuple[str, ...],
) -> None:
    """``forge connect replit --username NAME [--url URL]``."""

    @app.command(service_id, help=help_text)
    def _replit_add(  # noqa: ANN202
        username: Optional[str] = typer.Option(
            None, "--username", help="Replit username to spider."
        ),
        supabase_url: Optional[str] = typer.Option(
            None, "--url", help="Replit profile URL (optional override).",
        ),
        data_dir: Optional[Path] = typer.Option(
            None, "--data-dir", envvar="FORGE_DATA_DIR"
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Store the Replit username (no credential required)."""
        _apply_service_connection(
            service_id=service_id,
            cred_fields=cred_fields,
            required=required_fields,
            optional=optional_fields,
            flag_values={
                "username": username,
                "supabase_url": supabase_url,
            },
            data_dir=data_dir,
            json_output=json_output,
        )


def _register_censys_connect(
    app: typer.Typer,
    *,
    service_id: str,
    help_text: str,
    cred_fields: tuple[str, ...],
    required_fields: tuple[str, ...],
    optional_fields: tuple[str, ...],
) -> None:
    """``forge connect censys --api-id-env VAR --secret-env VAR``."""

    @app.command(service_id, help=help_text)
    def _censys_add(  # noqa: ANN202
        api_id_env: Optional[str] = typer.Option(
            None, "--api-id-env", help="Env var holding the Censys api_id.",
        ),
        api_id_stdin: bool = typer.Option(
            False, "--api-id-stdin", help="Read the Censys api_id from stdin.",
        ),
        secret_env: Optional[str] = typer.Option(
            None,
            "--secret-env",
            help="Env var holding the Censys api_secret.",
        ),
        secret_stdin: bool = typer.Option(
            False,
            "--secret-stdin",
            help="Read the Censys api_secret from stdin.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None, "--data-dir", envvar="FORGE_DATA_DIR"
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Store the Censys api_id + api_secret pair."""
        _apply_service_connection(
            service_id=service_id,
            cred_fields=cred_fields,
            required=required_fields,
            optional=optional_fields,
            flag_values={
                "api_id_env": api_id_env,
                "api_id_stdin": api_id_stdin,
                "secret_env": secret_env,
                "secret_stdin": secret_stdin,
            },
            data_dir=data_dir,
            json_output=json_output,
        )


def _register_dehashed_connect(
    app: typer.Typer,
    *,
    service_id: str,
    help_text: str,
    cred_fields: tuple[str, ...],
    required_fields: tuple[str, ...],
    optional_fields: tuple[str, ...],
) -> None:
    """``forge connect dehashed --email ADDR --key-env VAR``."""

    @app.command(service_id, help=help_text)
    def _dehashed_add(  # noqa: ANN202
        email: Optional[str] = typer.Option(
            None, "--email", help="DeHashed account email."
        ),
        key_env: Optional[str] = typer.Option(
            None,
            "--key-env",
            help="Env var holding the DeHashed API key.",
        ),
        key_stdin: bool = typer.Option(
            False, "--key-stdin", help="Read the DeHashed API key from stdin."
        ),
        data_dir: Optional[Path] = typer.Option(
            None, "--data-dir", envvar="FORGE_DATA_DIR"
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Store the DeHashed account email + API key."""
        _apply_service_connection(
            service_id=service_id,
            cred_fields=cred_fields,
            required=required_fields,
            optional=optional_fields,
            flag_values={
                "email": email,
                "key_env": key_env,
                "key_stdin": key_stdin,
            },
            data_dir=data_dir,
            json_output=json_output,
        )


def _apply_service_connection(
    *,
    service_id: str,
    cred_fields: tuple[str, ...],
    required: tuple[str, ...],
    optional: tuple[str, ...],
    flag_values: dict[str, Any],
    data_dir: Optional[Path],
    json_output: bool,
) -> None:
    """Shared tail-call for every ``forge connect <service>`` command."""
    try:
        resolved, sources = _resolve_service_fields(
            service_id,
            cred_fields=cred_fields,
            required=required,
            optional=optional,
            orgs=flag_values.get("orgs"),
            users=flag_values.get("users"),
            token_env=flag_values.get("token_env"),
            token_stdin=bool(flag_values.get("token_stdin")),
            key_env=flag_values.get("key_env"),
            key_stdin=bool(flag_values.get("key_stdin")),
            secret_env=flag_values.get("secret_env"),
            secret_stdin=bool(flag_values.get("secret_stdin")),
            api_id_env=flag_values.get("api_id_env"),
            api_id_stdin=bool(flag_values.get("api_id_stdin")),
            project_ref=flag_values.get("project_ref"),
            supabase_url=flag_values.get("supabase_url"),
            username=flag_values.get("username"),
            email=flag_values.get("email"),
        )
    except ConnectionError as exc:
        _emit_error(str(exc), json_output=json_output)
        raise typer.Exit(code=1)
    try:
        manager = _mk_manager(data_dir)
        manager.add_connection(
            service_id,
            credential_sources=sources,
            **resolved,
        )
    except ConnectionError as exc:
        _emit_error(str(exc), json_output=json_output)
        raise typer.Exit(code=1)
    payload = {
        "service": service_id,
        "connections_path": str(manager.config_path),
        "credential_sources": sources,
        "fields_set": sorted(resolved.keys()),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    console.print(f"[green]Stored[/green] {service_id} connection at {manager.config_path}")


# ----------------------------------------------------------------------
# forge scope
# ----------------------------------------------------------------------


def register_scope_commands(app: typer.Typer) -> None:
    """Register the ``forge scope`` sub-commands on ``app``."""

    @app.command("show")
    def scope_show(
        manifest: Path = typer.Option(
            Path("manifests") / "default.json",
            "--manifest",
            envvar="FORGE_SCOPE_MANIFEST",
            help="Scope manifest JSON path.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Print the current scope manifest."""
        payload = load_scope_manifest(manifest)
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        _print_scope_table(manifest, payload)

    @app.command("add-domain")
    def scope_add_domain(
        value: str = typer.Argument(..., help="Domain to add (e.g. example.com)."),
        manifest: Path = typer.Option(
            Path("manifests") / "default.json",
            "--manifest",
            envvar="FORGE_SCOPE_MANIFEST",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Append a domain to the scope manifest."""
        _append_scope_entry(manifest, "domain", value, json_output=json_output)

    @app.command("add-ip")
    def scope_add_ip(
        value: str = typer.Argument(..., help="IP or CIDR range (e.g. 10.0.0.0/24)."),
        manifest: Path = typer.Option(
            Path("manifests") / "default.json",
            "--manifest",
            envvar="FORGE_SCOPE_MANIFEST",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Append an IP or IP range to the scope manifest."""
        _append_scope_entry(manifest, "ip", value, json_output=json_output)

    @app.command("auto-expand")
    def scope_auto_expand(
        manifest: Path = typer.Option(
            Path("manifests") / "default.json",
            "--manifest",
            envvar="FORGE_SCOPE_MANIFEST",
        ),
        feed: Optional[Path] = typer.Option(
            None,
            "--feed",
            help=(
                "Target-feed.v1 JSON file to source candidates from. "
                "When omitted, imports/target-feed.json is used if present."
            ),
        ),
        apply: bool = typer.Option(
            False,
            "--apply",
            help="Write expanded manifest to disk. Default is preview-only.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Expand scope with safe discoveries (subdomains, IPs reverse-DNS'd to scope)."""
        feed_path = feed or Path("imports") / "target-feed.json"
        candidates = _load_feed_candidates(feed_path)
        result = expand_scope_from_feeds(manifest, candidates, apply=apply)
        if json_output:
            typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            return
        _print_scope_expansion(result)


# ----------------------------------------------------------------------
# forge targets add
# ----------------------------------------------------------------------


def register_targets_add_command(app: typer.Typer) -> None:
    """Register ``forge targets add`` on ``app`` (the targets Typer group)."""

    @app.command("add")
    def targets_add(
        value: Optional[str] = typer.Argument(
            None,
            help=(
                "Target seed (domain, URL, IP/CIDR, email, phone, @username, "
                "or quoted company/name)."
            ),
        ),
        github_owner: Optional[str] = typer.Option(
            None,
            "--github",
            help="GitHub org/user slug to spider using the stored connection.",
        ),
        supabase_project: Optional[str] = typer.Option(
            None,
            "--supabase",
            help="Supabase project ref to queue for scanning.",
        ),
        from_file: Optional[Path] = typer.Option(
            None,
            "--from-file",
            help="Text file with one target per line.",
        ),
        no_scope: bool = typer.Option(
            False,
            "--no-scope",
            help="Skip the automatic scope-manifest update.",
        ),
        engagement_id: Optional[int] = typer.Option(
            None,
            "--engagement",
            "-e",
            help="Reuse an existing engagement id instead of allocating a new one.",
        ),
        manifest: Path = typer.Option(
            Path("manifests") / "default.json",
            "--manifest",
            envvar="FORGE_SCOPE_MANIFEST",
        ),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            envvar="FORGE_DATA_DIR",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Add a seed target. Auto-detects type and updates the scope manifest."""
        auto_scope = not no_scope
        resolved_data_dir = _resolve_data_dir(data_dir)

        if github_owner:
            payload = _handle_github_target(
                github_owner, data_dir=resolved_data_dir, json_output=json_output
            )
            _print_or_json(payload, json_output=json_output)
            return
        if supabase_project:
            payload = _handle_supabase_target(
                supabase_project,
                data_dir=resolved_data_dir,
                json_output=json_output,
            )
            _print_or_json(payload, json_output=json_output)
            return

        values_to_add: list[str] = []
        if from_file is not None:
            try:
                raw = from_file.read_text(encoding="utf-8")
            except OSError as exc:
                _emit_error(f"cannot read {from_file}: {exc}", json_output=json_output)
                raise typer.Exit(code=1)
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                values_to_add.append(stripped)
        if value:
            values_to_add.insert(0, value)
        if not values_to_add:
            _emit_error(
                "no target supplied; pass a seed, --from-file, --github, or --supabase",
                json_output=json_output,
            )
            raise typer.Exit(code=2)

        results: list[dict[str, Any]] = []
        current_engagement = engagement_id
        for raw_value in values_to_add:
            try:
                result = add_target(
                    raw_value,
                    auto_scope=auto_scope,
                    engagement_id=current_engagement,
                    manifest_path=manifest,
                    data_dir=resolved_data_dir,
                )
            except ValueError as exc:
                results.append(
                    {
                        "value": raw_value,
                        "status": "error",
                        "detail": str(exc),
                    }
                )
                continue
            payload = result.to_dict()
            payload["status"] = "ok"
            results.append(payload)
            if current_engagement is None:
                current_engagement = result.engagement_id

        payload = {
            "schema_version": "forge.targets_add.v1",
            "manifest_path": str(manifest),
            "auto_scope": auto_scope,
            "results": results,
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        _print_targets_add_summary(payload)


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


def _mk_manager(data_dir: Path | None) -> ServiceConnectionManager:
    resolved = _resolve_data_dir(data_dir)
    return ServiceConnectionManager(resolved)


def _resolve_data_dir(data_dir: Path | None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    try:
        cfg = ForgeConfig.load()
    except Exception:  # noqa: BLE001
        return Path.cwd() / ".forge_data"
    return Path(cfg.data_dir)


def _resolve_service_fields(
    service_id: str,
    *,
    cred_fields: tuple[str, ...],
    required: tuple[str, ...],
    optional: tuple[str, ...],
    orgs: str | None,
    users: str | None,
    token_env: str | None,
    token_stdin: bool,
    key_env: str | None,
    key_stdin: bool,
    secret_env: str | None,
    secret_stdin: bool,
    api_id_env: str | None,
    api_id_stdin: bool,
    project_ref: str | None,
    supabase_url: str | None,
    username: str | None,
    email: str | None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Translate CLI options into (fields, credential_sources) for the manager."""
    fields: dict[str, Any] = {}
    sources: dict[str, str] = {}

    def _resolve_pair(
        field_name: str,
        env_name: str | None,
        read_stdin: bool,
    ) -> None:
        if field_name not in required and field_name not in optional:
            return
        if env_name:
            value, source = read_env_credential(env_name)
            fields[field_name] = value
            if field_name in cred_fields:
                sources[field_name] = source
        elif read_stdin:
            value, source = read_stdin_credential()
            fields[field_name] = value
            if field_name in cred_fields:
                sources[field_name] = source
        elif field_name in cred_fields and field_name in required:
            raise ConnectionError(
                f"service {service_id!r} requires --{field_name.replace('_', '-')}-env "
                f"or --{field_name.replace('_', '-')}-stdin"
            )

    _resolve_pair("token", token_env, token_stdin)
    _resolve_pair("key", key_env, key_stdin)
    _resolve_pair("api_secret", secret_env, secret_stdin)
    _resolve_pair("api_id", api_id_env, api_id_stdin)

    if "orgs" in optional and orgs:
        fields["orgs"] = orgs
    if "users" in optional and users:
        fields["users"] = users
    if "project_ref" in required and project_ref:
        fields["project_ref"] = project_ref
    if "url" in optional and supabase_url:
        fields["url"] = supabase_url
    if "username" in required and username:
        fields["username"] = username
    if "email" in required and email:
        fields["email"] = email
    return fields, sources


def _append_scope_entry(
    manifest_path: Path,
    kind: str,
    value: str,
    *,
    json_output: bool,
) -> None:
    manifest = load_scope_manifest(manifest_path)
    added = False
    if kind == "domain":
        normalized = value.strip().lower().lstrip("*.").strip(".")
        current = {str(d).lower().strip(".").lstrip("*.") for d in manifest.get("domains", [])}
        if normalized and normalized not in current:
            manifest.setdefault("domains", []).append(normalized)
            added = True
    elif kind == "ip":
        import ipaddress  # noqa: PLC0415

        try:
            net = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError as exc:
            _emit_error(f"invalid IP/CIDR {value!r}: {exc}", json_output=json_output)
            raise typer.Exit(code=1)
        canonical = str(net)
        current = set(manifest.get("ip_ranges", []))
        if canonical not in current:
            manifest.setdefault("ip_ranges", []).append(canonical)
            added = True
    else:  # pragma: no cover - exhaustive guard
        raise typer.BadParameter(f"unsupported scope kind {kind!r}")
    payload = {
        "manifest_path": str(manifest_path),
        "value": value,
        "added": added,
    }
    if added:
        write_scope_manifest(manifest_path, manifest)
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    verb = "Added" if added else "Already present"
    console.print(f"[green]{verb}[/green] {value} in {manifest_path}")


def _load_feed_candidates(feed_path: Path) -> list[dict[str, Any]]:
    if not feed_path.is_file():
        return []
    try:
        raw = feed_path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    if not isinstance(items, list):
        return []
    candidates: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            candidate = normalize_candidate(
                str(item.get("target_value") or item.get("value") or ""),
                seed_type=item.get("target_type") or item.get("seed_type"),
                related_domains=item.get("related_domains") or [],
            )
        except ValueError:
            continue
        candidates.append(candidate)
    return candidates


def _handle_github_target(
    owner: str,
    *,
    data_dir: Path,
    json_output: bool,
) -> dict[str, Any]:
    manager = ServiceConnectionManager(data_dir)
    connection = manager.get_connection("github")
    if connection is None:
        _emit_error(
            "no GitHub connection stored; run `forge connect github --token-env ...` first",
            json_output=json_output,
        )
        raise typer.Exit(code=1)
    token = str(connection.config.get("token") or "")
    if not token:
        _emit_error(
            "GitHub connection is missing a token value",
            json_output=json_output,
        )
        raise typer.Exit(code=1)
    try:
        result = spider_github(token, orgs=[owner.strip()])
    except GitHubSpiderError as exc:
        _emit_error(f"github spider error: {exc}", json_output=json_output)
        raise typer.Exit(code=1)
    return {
        "schema_version": "forge.targets_add.v1",
        "mode": "github_spider",
        "owner": owner,
        "result": result.to_dict(),
    }


def _handle_supabase_target(
    project_ref: str,
    *,
    data_dir: Path,
    json_output: bool,
) -> dict[str, Any]:
    manager = ServiceConnectionManager(data_dir)
    connection = manager.get_connection("supabase")
    stored_ref = ""
    if connection is not None:
        stored_ref = str(connection.config.get("project_ref") or "")
    return {
        "schema_version": "forge.targets_add.v1",
        "mode": "supabase",
        "project_ref": project_ref,
        "connection_present": connection is not None,
        "connection_project_ref": stored_ref,
        "note": (
            "Supabase scanning is wired through `forge automation feed-build` "
            "with imports/supabase-projects.local.json; `forge connect supabase` "
            "stores the credentials and this placeholder confirms the mapping."
        ),
    }


def _print_connection_table(summary: dict[str, Any]) -> None:
    table = Table(title=f"Connections ({summary['connections_path']})", box=box.SIMPLE)
    table.add_column("Service", style="bold")
    table.add_column("Added")
    table.add_column("Fields")
    table.add_column("Credentials")
    for connection in summary.get("connections", []):
        config = connection.get("config", {})
        sources = connection.get("credential_sources", {})
        field_pairs = ", ".join(
            f"{k}={v}" for k, v in config.items() if k not in sources
        )
        source_pairs = ", ".join(f"{k}:{v}" for k, v in sources.items())
        table.add_row(
            connection["service"],
            connection["added_at"],
            field_pairs or "-",
            source_pairs or "-",
        )
    console.print(table)
    console.print(
        "[dim]Supported services:[/dim] "
        + ", ".join(summary.get("available_services", []))
    )


def _print_scope_table(manifest_path: Path, payload: dict[str, Any]) -> None:
    table = Table(title=f"Scope ({manifest_path})", box=box.SIMPLE)
    table.add_column("Field", style="bold")
    table.add_column("Count")
    table.add_column("Values")
    for key in ("domains", "urls", "ip_ranges", "authorized_seeds"):
        values = payload.get(key) or []
        if isinstance(values, list):
            value_label = ", ".join(str(v) for v in values[:5])
            if len(values) > 5:
                value_label += f", … (+{len(values) - 5} more)"
        else:
            value_label = str(values)
        table.add_row(key, str(len(values) if isinstance(values, list) else 1), value_label)
    console.print(table)


def _print_scope_expansion(result: Any) -> None:
    table = Table(title="Scope auto-expansion", box=box.SIMPLE)
    table.add_column("Status", style="bold")
    table.add_column("Count")
    table.add_row("accepted", str(len(result.accepted)))
    table.add_row("review_required", str(len(result.review_required)))
    table.add_row("added_domains", str(len(result.added_domains)))
    table.add_row("added_urls", str(len(result.added_urls)))
    table.add_row("added_ip_ranges", str(len(result.added_ip_ranges)))
    table.add_row("unchanged", str(result.unchanged))
    console.print(table)


def _print_targets_add_summary(payload: dict[str, Any]) -> None:
    table = Table(title=f"Targets add ({payload['manifest_path']})", box=box.SIMPLE)
    table.add_column("Value", style="bold")
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("Engagement")
    table.add_column("Scope")
    for result in payload["results"]:
        status = result.get("status", "?")
        color = "green" if status == "ok" else "red"
        table.add_row(
            str(result.get("value") or result.get("canonical_value") or ""),
            f"[{color}]{status}[/{color}]",
            str(result.get("seed_type") or ""),
            str(result.get("engagement_id") or ""),
            "updated" if result.get("manifest_updated") else "unchanged",
        )
    console.print(table)


def _print_or_json(payload: dict[str, Any], *, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    console.print(json.dumps(payload, indent=2, sort_keys=True))


def _emit_error(message: str, *, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps({"error": message}, indent=2, sort_keys=True))
    else:
        console.print(f"[red]Error:[/red] {message}")


__all__ = [
    "register_connect_commands",
    "register_scope_commands",
    "register_targets_add_command",
]
