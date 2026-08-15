"""Compatibility imports for decorator-registered CLI command modules."""
from __future__ import annotations

import forge.cli_cloud  # noqa: F401
import forge.cli_demo  # noqa: F401
import forge.cli_graph  # noqa: F401
import forge.cli_osint  # noqa: F401
import forge.cli_post  # noqa: F401
import forge.cli_report  # noqa: F401
from forge.cli_cloud import (
    cloud_aws,
    cloud_azure,
    cloud_firebase,
    cloud_firebase_extract,
    cloud_supabase,
)
from forge.cli_graph import graph_build
from forge.cli_osint import (
    osint_accounts,
    osint_breach,
    osint_dehashed,
    osint_emailrep,
    osint_google,
    osint_gravatar,
    osint_harvest,
    osint_hibp,
    osint_instagram,
    osint_keyscan,
    osint_linkedin,
    osint_name,
    osint_phone,
    osint_shodan,
    osint_social,
    osint_urlscan,
    osint_usernames,
    osint_validate,
    osint_xposed,
)
from forge.cli_post import (
    _assert_offensive_cli,
    post_beacon,
    post_lateral,
    post_shell,
)
from forge.cli_report import report_generate

__all__ = [
    "_assert_offensive_cli",
    "cloud_aws",
    "cloud_azure",
    "cloud_firebase",
    "cloud_firebase_extract",
    "cloud_supabase",
    "graph_build",
    "osint_accounts",
    "osint_breach",
    "osint_dehashed",
    "osint_emailrep",
    "osint_google",
    "osint_gravatar",
    "osint_harvest",
    "osint_hibp",
    "osint_instagram",
    "osint_keyscan",
    "osint_linkedin",
    "osint_name",
    "osint_phone",
    "osint_shodan",
    "osint_social",
    "osint_urlscan",
    "osint_usernames",
    "osint_validate",
    "osint_xposed",
    "post_beacon",
    "post_lateral",
    "post_shell",
    "report_generate",
]
