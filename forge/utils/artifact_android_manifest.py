from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_ANDROID_PACKAGE_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def android_manifest_artifact_label(value: str | Path) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name
    return "android-manifest" if name.lower() == "androidmanifest.xml" else ""


def android_manifest_package_names(text: str) -> list[str]:
    root = _xml_root(text)
    if root is None or _local_name(root.tag) != "manifest":
        return []
    package_name = _valid_android_package(root.attrib.get("package"))
    return [package_name] if package_name else []


def android_manifest_urls(text: str) -> list[str]:
    root = _xml_root(text)
    if root is None:
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for intent_filter in root.iter():
        if _local_name(intent_filter.tag) != "intent-filter":
            continue
        if not _intent_filter_is_public_deep_link(intent_filter):
            continue
        for data in intent_filter:
            if _local_name(data.tag) != "data":
                continue
            url = _data_deep_link_url(data)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _xml_root(text: str) -> ElementTree.Element | None:
    try:
        return ElementTree.fromstring(str(text or "")[:256 * 1024])
    except Exception:  # noqa: BLE001
        return None


def _local_name(tag: object) -> str:
    value = str(tag or "")
    return value.rsplit("}", 1)[-1] if "}" in value else value


def _android_attr(element: ElementTree.Element, name: str) -> str:
    return str(element.attrib.get(f"{_ANDROID_NS}{name}") or element.attrib.get(f"android:{name}") or "").strip()


def _valid_android_package(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 255:
        return ""
    return candidate if _ANDROID_PACKAGE_RE.fullmatch(candidate) else ""


def _intent_filter_is_public_deep_link(element: ElementTree.Element) -> bool:
    has_view = False
    has_browsable = False
    for child in element:
        local = _local_name(child.tag)
        name = _android_attr(child, "name")
        if local == "action" and name == "android.intent.action.VIEW":
            has_view = True
        elif local == "category" and name == "android.intent.category.BROWSABLE":
            has_browsable = True
    return has_view and has_browsable


def _data_deep_link_url(element: ElementTree.Element) -> str:
    scheme = _android_attr(element, "scheme").lower()
    if scheme not in {"http", "https"}:
        return ""
    host = _safe_host(_android_attr(element, "host"))
    if not host:
        return ""
    path = _safe_path(
        _android_attr(element, "path")
        or _android_attr(element, "pathPrefix")
        or _android_attr(element, "pathPattern")
    )
    return f"{scheme}://{host}{path}"


def _safe_host(value: str) -> str:
    host = str(value or "").strip().lower().strip(".")
    if not host or _looks_templated(host) or "*" in host or ":" in host:
        return ""
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local")):
        return ""
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        parsed_ip = None
    if parsed_ip is not None:
        if (
            parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_multicast
            or parsed_ip.is_private
            or parsed_ip.is_unspecified
        ):
            return ""
        return str(parsed_ip)
    return host if _HOST_RE.fullmatch(host) else ""


def _safe_path(value: str) -> str:
    path = str(value or "").strip()
    if not path:
        return ""
    if _looks_templated(path) or "*" in path:
        return ""
    if not path.startswith("/"):
        path = f"/{path}"
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc:
        return ""
    return path


def _looks_templated(value: str) -> bool:
    return any(marker in value for marker in ("{", "}", "${", "$(", "{{", "}}", "<", ">"))
