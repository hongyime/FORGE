from __future__ import annotations

from urllib.parse import quote


def long_tail_package_url_registry_candidate(ecosystem: str, package_path: str) -> str:
    package = str(package_path or "").strip("/")
    if not package:
        return ""
    encoded_path = quote(package, safe="@/._-+~")
    encoded_leaf = quote(package.rsplit("/", 1)[-1], safe="@._-+~")
    normalized_ecosystem = str(ecosystem or "").strip().lower()

    if normalized_ecosystem in {"swift", "swiftpm"}:
        parts = [part for part in package.split("/") if part]
        if len(parts) >= 2:
            return f"https://swiftpackageindex.com/{quote(parts[0], safe='._-+~')}/{quote(parts[1], safe='._-+~')}"
        return ""
    if normalized_ecosystem in {"cocoapods", "pod"}:
        return f"https://cocoapods.org/pods/{encoded_leaf}"
    if normalized_ecosystem in {"pub", "dart"}:
        return f"https://pub.dev/packages/{encoded_leaf}"
    if normalized_ecosystem in {"hex", "hexpm"}:
        return f"https://hex.pm/packages/{encoded_leaf}"
    if normalized_ecosystem in {"cran", "r"}:
        return f"https://cran.r-project.org/package={encoded_leaf}"
    if normalized_ecosystem in {"huggingface", "hf"}:
        return f"https://huggingface.co/{encoded_path}"
    return ""
