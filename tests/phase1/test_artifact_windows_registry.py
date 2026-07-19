from __future__ import annotations

import pytest

from forge.utils.artifact_windows_registry import windows_registry_hive_artifact_label


@pytest.mark.parametrize(
    "value",
    [
        "NTUSER.DAT",
        "Users/Alice/NTUSER.DAT",
        "42-UsrClass.dat",
        "Users/Alice/AppData/Local/Microsoft/Windows/UsrClass.dat",
        "Windows/System32/config/SOFTWARE",
        "Windows/System32/config/RegBack/SYSTEM",
        "Windows/System32/config/SAM",
        "Boot/BCD",
        "Windows/AppCompat/Programs/Amcache.hve",
        "SOFTWARE.reghive",
    ],
)
def test_windows_registry_hive_artifact_label_recognizes_hive_paths(value: str) -> None:
    assert windows_registry_hive_artifact_label(value) == "windows-registry-hive"


@pytest.mark.parametrize(
    "value",
    [
        "SOFTWARE",
        "SYSTEM",
        "config/SOFTWARE",
        "browser/History",
        "settings.dat",
        "UsrClass.dat.bak",
        "system32/config.txt",
    ],
)
def test_windows_registry_hive_artifact_label_avoids_generic_false_positives(
    value: str,
) -> None:
    assert windows_registry_hive_artifact_label(value) == ""
