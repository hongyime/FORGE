"""forge/seeds/api_spec_parser.py — OpenAPI / Swagger / Postman parsing (Wave 2 #21).

Accepts a local file path to an OpenAPI 3.x (JSON or YAML), Swagger 2.0,
or Postman collection v2.x export and extracts in-scope URL seeds that
can join the normal kill-chain crawl queue. Static parsing only:

* No network calls.
* No subprocess execution.
* No evaluation of embedded expressions, scripts, or test blocks.
* File size and endpoint counts are bounded so a hostile spec cannot
  exhaust memory or balloon the recursion queue.

Scope enforcement:

* ``extract_url_seeds`` only emits URLs whose host matches a domain
  entry in the supplied scope manifest. Wildcard-prefixed scope domains
  are supported (``*.example.com`` → ``example.com`` and any subdomain).
* URL manifest entries anchor emitted seeds too — if the scope lists
  ``https://portal.example.com/`` as the only authorized prefix, only
  endpoints under that prefix are returned.
* Discovered endpoints without an in-scope base URL are dropped
  silently (counted in ``out_of_scope_count`` for reporting).

Public contract:

    from forge.seeds.api_spec_parser import (
        parse_api_spec_file,
        extract_url_seeds,
        ApiSpecParseError,
    )

    spec = parse_api_spec_file(Path("openapi.yaml"))
    result = extract_url_seeds(spec, scope_manifest={"domains": ["api.example.com"]})
    for url in result["urls"]:
        ...  # feed into the kill-chain URL seed queue
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

__all__ = [
    "API_SPEC_SUFFIXES",
    "ApiSpecParseError",
    "classify_api_spec_value",
    "extract_url_seeds",
    "parse_api_spec_file",
    "parse_api_spec_text",
]


# ---------------------------------------------------------------------------
# Bounds — keep hostile specs from spamming the queue or exhausting memory.
# ---------------------------------------------------------------------------


MAX_SPEC_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MiB
MAX_EXTRACTED_URL_SEEDS: int = 5_000
MAX_RAW_PATHS: int = 20_000


API_SPEC_SUFFIXES: tuple[str, ...] = (".json", ".yaml", ".yml")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ApiSpecParseError(ValueError):
    """Raised when the file cannot be classified as a supported API spec."""


# ---------------------------------------------------------------------------
# File-level entry point
# ---------------------------------------------------------------------------


def parse_api_spec_file(path: str | Path) -> dict[str, Any]:
    """Load *path* and parse it as an OpenAPI/Swagger/Postman spec.

    Returns a normalized dict:

        {
            "format": "openapi3" | "swagger2" | "postman2",
            "title":  str,
            "version": str,
            "base_urls": list[str],
            "paths": list[str],         # raw templated paths/endpoints
            "endpoints": list[dict],    # [{"method", "path"}]
            "source_path": str,
        }

    Raises :class:`ApiSpecParseError` if the file is missing, too large,
    not valid JSON/YAML, or does not look like a supported spec.
    """
    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise ApiSpecParseError(f"api spec file not found: {resolved}")
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise ApiSpecParseError(f"cannot stat api spec: {exc}") from exc
    if size > MAX_SPEC_FILE_BYTES:
        raise ApiSpecParseError(
            f"api spec file too large: {size} bytes (cap {MAX_SPEC_FILE_BYTES})"
        )
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ApiSpecParseError(f"cannot read api spec: {exc}") from exc
    parsed = parse_api_spec_text(text, suffix=resolved.suffix)
    parsed["source_path"] = str(resolved)
    return parsed


def parse_api_spec_text(text: str, *, suffix: str | None = None) -> dict[str, Any]:
    """Parse an API spec payload supplied directly as text.

    *suffix* is an optional file extension hint (``.json``/``.yaml``/``.yml``);
    when None the parser tries JSON first then YAML.
    """
    content = text or ""
    if not content.strip():
        raise ApiSpecParseError("api spec text is empty")

    document = _load_document(content, suffix=suffix)
    if not isinstance(document, dict):
        raise ApiSpecParseError("api spec root must be a JSON/YAML object")

    if "openapi" in document and str(document["openapi"]).startswith("3."):
        return _parse_openapi3(document)
    if "swagger" in document and str(document["swagger"]).startswith("2."):
        return _parse_swagger2(document)
    info = document.get("info")
    if isinstance(info, dict) and "schema" in info and "postman" in str(info.get("schema", "")).lower():
        return _parse_postman(document)
    if "item" in document and isinstance(document.get("item"), list):
        # Looser Postman match for exports with a stripped `info.schema`.
        return _parse_postman(document)

    raise ApiSpecParseError(
        "unsupported api spec: expected OpenAPI 3.x, Swagger 2.0, or Postman v2 shape"
    )


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------


_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _parse_openapi3(document: dict[str, Any]) -> dict[str, Any]:
    info = _info_block(document)
    servers = _collect_openapi_servers(document.get("servers"))
    paths_obj = document.get("paths")
    endpoints, raw_paths = _collect_openapi_paths(paths_obj)
    return {
        "format": "openapi3",
        "title": str(info.get("title") or ""),
        "version": str(info.get("version") or ""),
        "base_urls": servers,
        "paths": raw_paths,
        "endpoints": endpoints,
    }


def _parse_swagger2(document: dict[str, Any]) -> dict[str, Any]:
    info = _info_block(document)
    host = str(document.get("host") or "").strip()
    base_path = str(document.get("basePath") or "/").strip() or "/"
    schemes = document.get("schemes") or []
    base_urls: list[str] = []
    if host:
        for scheme in schemes or ["https"]:
            scheme_text = str(scheme or "").strip().lower() or "https"
            if scheme_text not in {"http", "https"}:
                continue
            if not base_path.startswith("/"):
                base_path = "/" + base_path
            base_urls.append(f"{scheme_text}://{host}{base_path}".rstrip("/"))
    paths_obj = document.get("paths")
    endpoints, raw_paths = _collect_openapi_paths(paths_obj)
    return {
        "format": "swagger2",
        "title": str(info.get("title") or ""),
        "version": str(info.get("version") or ""),
        "base_urls": base_urls,
        "paths": raw_paths,
        "endpoints": endpoints,
    }


def _parse_postman(document: dict[str, Any]) -> dict[str, Any]:
    info = _info_block(document)
    base_urls: list[str] = []
    endpoints: list[dict[str, str]] = []
    raw_paths: list[str] = []
    collection_variables = _postman_variables(document.get("variable"))
    _walk_postman_items(
        document.get("item") or [],
        base_urls=base_urls,
        endpoints=endpoints,
        raw_paths=raw_paths,
        variables=collection_variables,
    )
    return {
        "format": "postman2",
        "title": str(info.get("title") or ""),
        "version": str(info.get("_postman_id") or info.get("version") or ""),
        "base_urls": _dedupe_preserve_order(base_urls),
        "paths": raw_paths[:MAX_RAW_PATHS],
        "endpoints": endpoints,
    }


# ---------------------------------------------------------------------------
# OpenAPI helpers
# ---------------------------------------------------------------------------


def _collect_openapi_servers(servers_obj: Any) -> list[str]:
    base_urls: list[str] = []
    if not isinstance(servers_obj, list):
        return base_urls
    for entry in servers_obj:
        if not isinstance(entry, dict):
            continue
        url_template = str(entry.get("url") or "").strip()
        if not url_template:
            continue
        variables = entry.get("variables") if isinstance(entry.get("variables"), dict) else {}
        resolved = _resolve_openapi_server_variables(url_template, variables)
        if resolved:
            base_urls.append(resolved)
    return _dedupe_preserve_order(base_urls)


def _resolve_openapi_server_variables(
    url_template: str, variables: dict[str, Any]
) -> str | None:
    text = url_template
    for name, spec in variables.items():
        default = spec.get("default") if isinstance(spec, dict) else None
        if default is None:
            continue
        text = text.replace("{" + str(name) + "}", str(default))
    text = text.strip()
    if not text:
        return None
    if text.startswith("/"):
        # OpenAPI permits relative server URLs; a scope-aware pipeline
        # cannot anchor these without an operator-supplied host, so we
        # drop them here and expect downstream code to pair the spec
        # with scope manifest `urls`.
        return None
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None
    return text.rstrip("/")


def _collect_openapi_paths(
    paths_obj: Any,
) -> tuple[list[dict[str, str]], list[str]]:
    endpoints: list[dict[str, str]] = []
    raw_paths: list[str] = []
    if not isinstance(paths_obj, dict):
        return endpoints, raw_paths
    for path, path_item in paths_obj.items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        if len(raw_paths) >= MAX_RAW_PATHS:
            break
        raw_paths.append(path)
        if not isinstance(path_item, dict):
            continue
        for method_name, operation in path_item.items():
            if not isinstance(method_name, str):
                continue
            lowered = method_name.lower()
            if lowered not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                # Still emit the raw path with its method; description-less
                # entries are valid in OpenAPI.
                endpoints.append({"method": lowered.upper(), "path": path})
                continue
            endpoints.append({"method": lowered.upper(), "path": path})
    return endpoints, raw_paths


# ---------------------------------------------------------------------------
# Postman helpers
# ---------------------------------------------------------------------------


_POSTMAN_VAR_RE = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")


def _postman_variables(variable_obj: Any) -> dict[str, str]:
    variables: dict[str, str] = {}
    if not isinstance(variable_obj, list):
        return variables
    for entry in variable_obj:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("key") or "").strip()
        value = entry.get("value")
        if key and isinstance(value, (str, int, float)):
            variables[key] = str(value)
    return variables


def _walk_postman_items(
    items: list[Any],
    *,
    base_urls: list[str],
    endpoints: list[dict[str, str]],
    raw_paths: list[str],
    variables: dict[str, str],
) -> None:
    for entry in items:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("item"), list):
            _walk_postman_items(
                entry["item"],
                base_urls=base_urls,
                endpoints=endpoints,
                raw_paths=raw_paths,
                variables=variables,
            )
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "GET").strip().upper() or "GET"
        url_obj = request.get("url")
        if isinstance(url_obj, str):
            resolved_url = _substitute_postman_vars(url_obj, variables)
        elif isinstance(url_obj, dict):
            raw = url_obj.get("raw")
            if isinstance(raw, str) and raw.strip():
                resolved_url = _substitute_postman_vars(raw, variables)
            else:
                protocol = str(url_obj.get("protocol") or "https").strip().lower() or "https"
                host_parts = url_obj.get("host")
                if isinstance(host_parts, list):
                    host = ".".join(str(part) for part in host_parts if str(part).strip())
                else:
                    host = str(host_parts or "")
                path_parts = url_obj.get("path")
                if isinstance(path_parts, list):
                    path = "/".join(str(part) for part in path_parts if str(part) != "")
                    if path and not path.startswith("/"):
                        path = "/" + path
                else:
                    path = str(path_parts or "")
                resolved_url = _substitute_postman_vars(f"{protocol}://{host}{path}", variables)
        else:
            continue
        if not resolved_url:
            continue
        parsed = urlsplit(resolved_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        base = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        base_urls.append(base.rstrip("/"))
        if parsed.path:
            if len(raw_paths) < MAX_RAW_PATHS:
                raw_paths.append(parsed.path)
            endpoints.append({"method": method, "path": parsed.path})


def _substitute_postman_vars(text: str, variables: dict[str, str]) -> str:
    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in variables:
            return variables[name]
        return match.group(0)

    return _POSTMAN_VAR_RE.sub(repl, text)


# ---------------------------------------------------------------------------
# URL extraction + scope enforcement
# ---------------------------------------------------------------------------


def extract_url_seeds(
    spec: dict[str, Any],
    *,
    scope_manifest: dict[str, Any] | None = None,
    base_url_override: str | None = None,
) -> dict[str, Any]:
    """Materialize absolute URL seeds from a parsed spec document.

    *scope_manifest* uses the FORGE scope manifest shape: ``domains`` and
    ``urls`` lists bound the emitted seeds. Hosts/URLs outside the
    manifest are dropped (counted in ``out_of_scope_count``).

    *base_url_override* lets an operator anchor relative or
    missing-base-URL specs on a scope manifest URL entry when the spec
    file itself did not declare a server. The override is still
    scope-checked.

    Returns a dict::

        {
            "format": "openapi3" | ...,
            "base_urls": [...],       # scope-filtered base URLs
            "urls": [...],            # scope-filtered endpoint URLs
            "endpoint_count": int,
            "out_of_scope_count": int,
            "limit_reached": bool,
        }
    """
    allowed_domains, allowed_url_prefixes = _scope_filters(scope_manifest or {})
    base_urls_raw = list(spec.get("base_urls") or [])
    if base_url_override:
        base_urls_raw.insert(0, str(base_url_override).strip())
    base_urls_filtered = [
        _normalize_base_url(url)
        for url in base_urls_raw
        if _normalize_base_url(url)
    ]
    base_urls_scope_ok = [
        url
        for url in base_urls_filtered
        if _base_url_in_scope(url, allowed_domains, allowed_url_prefixes)
    ]
    base_urls_scope_ok = _dedupe_preserve_order(base_urls_scope_ok)

    extracted_urls: list[str] = []
    out_of_scope = 0
    limit_reached = False

    endpoints = spec.get("endpoints") or []
    paths = spec.get("paths") or []

    endpoint_values: list[str] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        candidate = endpoint.get("path")
        if isinstance(candidate, str) and candidate.strip():
            endpoint_values.append(candidate.strip())
    if not endpoint_values:
        for path in paths:
            if isinstance(path, str) and path.strip():
                endpoint_values.append(path.strip())

    seen: set[str] = set()
    anchors = base_urls_scope_ok or [""]
    for raw_path in endpoint_values:
        candidate_path = raw_path if raw_path.startswith("/") else "/" + raw_path
        for base in anchors:
            if not base:
                # No scope-matched base URL available for this spec.
                out_of_scope += 1
                continue
            absolute_url = base.rstrip("/") + candidate_path
            if not _url_in_scope(absolute_url, allowed_domains, allowed_url_prefixes):
                out_of_scope += 1
                continue
            if absolute_url in seen:
                continue
            if len(extracted_urls) >= MAX_EXTRACTED_URL_SEEDS:
                limit_reached = True
                break
            seen.add(absolute_url)
            extracted_urls.append(absolute_url)
        if limit_reached:
            break

    return {
        "format": spec.get("format"),
        "base_urls": base_urls_scope_ok,
        "urls": extracted_urls,
        "endpoint_count": len(endpoint_values),
        "out_of_scope_count": out_of_scope,
        "limit_reached": limit_reached,
    }


# ---------------------------------------------------------------------------
# Classification helper (used by seed auto-detection)
# ---------------------------------------------------------------------------


def classify_api_spec_value(value: str) -> bool:
    """Return True when *value* looks like an api_spec seed reference.

    The classifier is intentionally conservative — it only matches when
    the value points at a local JSON/YAML file that at least opens and
    looks like one of the supported spec shapes. This keeps generic
    ``.json`` paths out of the api_spec classification unless they
    actually contain an OpenAPI/Swagger/Postman document.
    """
    text = str(value or "").strip()
    if not text:
        return False
    normalized = text.lower()
    if normalized.startswith("file://"):
        normalized = normalized[len("file://") :]
        text = text[len("file://") :]
    if not any(normalized.endswith(suffix) for suffix in API_SPEC_SUFFIXES):
        return False
    path = Path(text).expanduser()
    if not path.is_file():
        return False
    try:
        if path.stat().st_size > MAX_SPEC_FILE_BYTES:
            return False
    except OSError:
        return False
    try:
        parsed = parse_api_spec_file(path)
    except (ApiSpecParseError, OSError):
        return False
    return parsed.get("format") in {"openapi3", "swagger2", "postman2"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _info_block(document: dict[str, Any]) -> dict[str, Any]:
    info = document.get("info")
    return info if isinstance(info, dict) else {}


def _load_document(content: str, *, suffix: str | None) -> Any:
    normalized_suffix = (suffix or "").lower()
    if normalized_suffix == ".json":
        return _try_json(content, required=True)
    if normalized_suffix in {".yaml", ".yml"}:
        return _try_yaml(content, required=True)

    # Autodetect: JSON first (fast path), fall back to YAML.
    parsed = _try_json(content)
    if parsed is not None:
        return parsed
    parsed = _try_yaml(content)
    if parsed is None:
        raise ApiSpecParseError("api spec is neither valid JSON nor YAML")
    return parsed


def _try_json(content: str, *, required: bool = False) -> Any:
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        if required:
            raise ApiSpecParseError(f"invalid JSON api spec: {exc}") from exc
        return None


def _try_yaml(content: str, *, required: bool = False) -> Any:
    try:
        import yaml  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - optional dep guard
        if required:
            raise ApiSpecParseError("PyYAML is required to parse YAML api specs") from exc
        return None
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        if required:
            raise ApiSpecParseError(f"invalid YAML api spec: {exc}") from exc
        return None


def _scope_filters(
    scope_manifest: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Return normalized (allowed_hosts, allowed_url_prefixes)."""
    domains_source = scope_manifest.get("domains") or scope_manifest.get("domain_allowlist") or []
    urls_source = scope_manifest.get("urls") or scope_manifest.get("url_prefixes") or []
    allowed_domains: list[str] = []
    for entry in domains_source:
        text = str(entry or "").strip().lower()
        if not text:
            continue
        if text.startswith("*."):
            text = text[2:]
        allowed_domains.append(text.strip(".").rstrip("/"))
    allowed_url_prefixes: list[str] = []
    for entry in urls_source:
        text = str(entry or "").strip()
        if not text:
            continue
        if text.startswith("*"):
            # URL wildcards aren't honored for OPSEC — the manifest should
            # declare concrete host prefixes.
            continue
        parsed = urlsplit(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        allowed_url_prefixes.append(text.rstrip("/"))
    return _dedupe_preserve_order(allowed_domains), _dedupe_preserve_order(allowed_url_prefixes)


def _url_in_scope(
    url: str,
    allowed_domains: list[str],
    allowed_url_prefixes: list[str],
) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().strip(".")
    if scheme not in {"http", "https"} or not host:
        return False

    if not allowed_domains and not allowed_url_prefixes:
        # Fail closed: no scope manifest ⇒ no in-scope URLs.
        return False

    if allowed_url_prefixes:
        normalized = url.rstrip("/")
        if any(normalized.startswith(prefix.rstrip("/")) for prefix in allowed_url_prefixes):
            return True

    for domain in allowed_domains:
        if not domain:
            continue
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _base_url_in_scope(
    base_url: str,
    allowed_domains: list[str],
    allowed_url_prefixes: list[str],
) -> bool:
    """Permissive base-URL filter.

    A spec base URL is kept when:

    * Its host matches any allowed domain, OR
    * Any allowed URL prefix shares its host and either is a prefix of
      the base URL or starts with the base URL (so an operator who
      declared a sub-path prefix still lets the base URL survive and
      produce the final absolute endpoint URL, which is then re-checked
      with :func:`_url_in_scope`).
    """
    if not base_url:
        return False
    parsed = urlparse(base_url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().strip(".")
    if scheme not in {"http", "https"} or not host:
        return False
    if not allowed_domains and not allowed_url_prefixes:
        return False
    for domain in allowed_domains:
        if not domain:
            continue
        if host == domain or host.endswith("." + domain):
            return True
    normalized_base = base_url.rstrip("/")
    for prefix in allowed_url_prefixes:
        normalized_prefix = prefix.rstrip("/")
        if not normalized_prefix:
            continue
        if normalized_base.startswith(normalized_prefix) or normalized_prefix.startswith(
            normalized_base
        ):
            return True
    return False


def _normalize_base_url(url: str) -> str | None:
    text = str(url or "").strip()
    if not text:
        return None
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return text.rstrip("/")


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
