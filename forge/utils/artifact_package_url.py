from __future__ import annotations

from urllib.parse import quote, unquote


def package_url_registry_candidate(package_type: str, body: str) -> str:
    ecosystem = str(package_type or "").strip().lower()
    package_path = package_url_package_path(body, ecosystem=ecosystem)
    if not ecosystem or not package_path:
        return ""
    encoded_path = quote(package_path, safe="@/._-+~")
    encoded_leaf = quote(package_path.rsplit("/", 1)[-1], safe="@._-+~")

    if ecosystem == "npm":
        return f"https://www.npmjs.com/package/{encoded_path}"
    if ecosystem in {"pypi", "python"}:
        return f"https://pypi.org/project/{encoded_leaf}/"
    if ecosystem in {"gem", "rubygems"}:
        return f"https://rubygems.org/gems/{encoded_leaf}"
    if ecosystem in {"cargo", "crate", "crates"}:
        return f"https://crates.io/crates/{encoded_leaf}"
    if ecosystem == "nuget":
        return f"https://www.nuget.org/packages/{encoded_leaf}"
    if ecosystem == "composer":
        return f"https://packagist.org/packages/{encoded_path}"
    if ecosystem == "maven":
        parts = [part for part in package_path.split("/") if part]
        if len(parts) >= 2:
            group_id = quote(parts[-2], safe="._-+~")
            artifact_id = quote(parts[-1], safe="._-+~")
            return f"https://central.sonatype.com/artifact/{group_id}/{artifact_id}"
        return ""
    if ecosystem in {"github", "githubactions"}:
        parts = [part for part in package_path.split("/") if part]
        if len(parts) >= 2:
            owner = quote(parts[0], safe="._-+~")
            repo = quote(parts[1], safe="._-+~")
            return f"https://github.com/{owner}/{repo}"
        return ""
    if ecosystem in {"golang", "go"}:
        return f"https://pkg.go.dev/{encoded_path}"
    if ecosystem in {"docker", "oci"}:
        docker_path = package_path if "/" in package_path else f"library/{package_path}"
        return f"https://hub.docker.com/r/{quote(docker_path, safe='/._-+~')}"

    return long_tail_package_url_registry_candidate(ecosystem, package_path)


def package_url_package_path(body: str, *, ecosystem: str) -> str:
    package_path = unquote(str(body or "").strip()).strip("/")
    if not package_path:
        return ""
    package_path = package_path.split("#", 1)[0].split("?", 1)[0].strip("/")
    if not package_path:
        return ""
    version_index = package_path.rfind("@")
    if version_index > 0:
        if ecosystem == "npm" and package_path.startswith("@"):
            namespace_slash = package_path.find("/")
            if version_index > namespace_slash:
                package_path = package_path[:version_index]
        else:
            package_path = package_path[:version_index]
    return package_path.strip("/")


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
