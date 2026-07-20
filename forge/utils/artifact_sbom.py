from __future__ import annotations

_MULTISUFFIX_FORMAT_LABELS = (
    ((".cyclonedx.json", ".cyclonedx.xml", ".cyclonedx.yaml", ".cyclonedx.yml"), "cyclonedx"),
    ((".cdx.json", ".cdx.xml", ".cdx.yaml", ".cdx.yml"), "cdx"),
    ((".spdx.json", ".spdx.yaml", ".spdx.yml"), "spdx"),
    ((".syft.json", ".syft.yaml", ".syft.yml"), "syft"),
)


def sbom_multisuffix_format_label(name: str) -> str:
    lowered = str(name or "").strip().lower()
    for suffixes, label in _MULTISUFFIX_FORMAT_LABELS:
        if any(lowered.endswith(suffix) for suffix in suffixes):
            return label
    return ""
