from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_remote_artifact_url,
    _suffix_from_content_type,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_virtual_machine_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_virtual_machine_configs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    vmx_path = artifact_root / "workstation.vmx"
    vmx_path.write_text(
        "\n".join(
            [
                'annotation = "vmx-owner@acme.example"',
                'guestinfo.portal = "https://vmx.acme.example/portal"',
                'guestinfo.firebase = "https://vmx-firebase.firebaseio.com"',
                'guestinfo.supabase = "https://vmxvault.supabase.co/rest/v1/vms"',
                'guestinfo.bucket = "s3://acme-vmx-bucket/vm/config"',
            ]
        ),
        encoding="utf-8",
    )

    vbox_path = artifact_root / "virtualbox.vbox"
    vbox_path.write_text(
        """
        <VirtualBox>
          <Machine name="Acme VM">
            <Description>vbox-owner@acme.example</Description>
            <ExtraDataItem name="portal" value="https://vbox.acme.example/console" />
            <ExtraDataItem name="storage" value="gs://acme-vbox-gcs/vms/virtualbox.vbox" />
            <ExtraDataItem name="supabase" value="https://vboxvault.supabase.co/rest/v1/vms" />
          </Machine>
        </VirtualBox>
        """,
        encoding="utf-8",
    )

    vagrant_path = artifact_root / "Vagrantfile"
    vagrant_path.write_text(
        dedent(
            """
            Vagrant.configure("2") do |config|
              config.vm.hostname = "web.vagrant.acme.example"
              api.vm.hostname = "api.vagrant.acme.example"
              config.vm.provision "shell", inline: "curl https://vagrant.acme.example/bootstrap"
              config.vm.provision "shell", inline: "echo vagrant-owner@acme.example"
              config.vm.provision "shell", inline: "echo https://vagrant-firebase.firebaseio.com"
              config.vm.provision "shell", inline: "echo s3://acme-vagrant-bucket/vm/Vagrantfile"
              config.vm.hostname = "https://vagrantvault.supabase.co/rest/v1/vms"
            end
            """
        ).strip(),
        encoding="utf-8",
    )

    archive_path = artifact_root / "vm-configs.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "vmware/team.vmxf",
            "\n".join(
                [
                    "<Foundry>",
                    "<Owner>vmxf-owner@acme.example</Owner>",
                    "<Url>https://vmxf.acme.example/inventory</Url>",
                    "<Firebase>https://vmxf-firebase.firebaseio.com</Firebase>",
                    "</Foundry>",
                ]
            ),
        )
        zf.writestr(
            "parallels/guest.pvs",
            "\n".join(
                [
                    "<ParallelsVM>",
                    "<Owner>pvs-owner@acme.example</Owner>",
                    "<Url>https://pvs.acme.example/control</Url>",
                    "<Bucket>s3://acme-pvs-bucket/parallels/guest.pvs</Bucket>",
                    "</ParallelsVM>",
                ]
            ),
        )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/workstation.vmx") == "config"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/virtualbox.vbox") == "config"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/virtualbox.vbox-prev")
        == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/team.vmxf") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/guest.pvs") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/Vagrantfile") == "config"
    assert _artifact_format_label("Vagrantfile") == "vagrantfile"
    assert _suffix_from_content_type("application/x-vmware-vmx") == ".vmx"
    assert _suffix_from_content_type("application/x-virtualbox-vbox") == ".vbox"
    assert _suffix_from_content_type("application/x-parallels-vm-config") == ".pvs"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 12
    assert summary.firebase_projects >= 3

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "vmx-owner@acme.example" in emails
        assert "vbox-owner@acme.example" in emails
        assert "vmxf-owner@acme.example" in emails
        assert "pvs-owner@acme.example" in emails
        assert "vagrant-owner@acme.example" in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("vmx-owner@acme.example", "email") in seeds
        assert ("vbox-owner@acme.example", "email") in seeds
        assert ("vmxf-owner@acme.example", "email") in seeds
        assert ("pvs-owner@acme.example", "email") in seeds
        assert ("vagrant-owner@acme.example", "email") in seeds
        assert ("https://vmx.acme.example/portal", "url") in seeds
        assert ("https://vbox.acme.example/console", "url") in seeds
        assert ("https://vmxf.acme.example/inventory", "url") in seeds
        assert ("https://pvs.acme.example/control", "url") in seeds
        assert ("https://vagrant.acme.example/bootstrap", "url") in seeds
        assert ("https://vmxvault.supabase.co/rest/v1/vms", "url") in seeds
        assert ("https://vboxvault.supabase.co/rest/v1/vms", "url") in seeds
        assert ("https://vagrantvault.supabase.co/rest/v1/vms", "url") in seeds
        assert ("vmx.acme.example", "subdomain") in seeds
        assert ("vbox.acme.example", "subdomain") in seeds
        assert ("vmxf.acme.example", "subdomain") in seeds
        assert ("pvs.acme.example", "subdomain") in seeds
        assert ("web.vagrant.acme.example", "subdomain") in seeds
        assert ("api.vagrant.acme.example", "subdomain") in seeds
        assert ("vmxvault.supabase.co", "subdomain") not in seeds
        assert ("vboxvault.supabase.co", "subdomain") not in seeds
        assert ("vagrantvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-pvs-bucket") in cloud_assets
        assert ("aws_s3", "acme-vagrant-bucket") in cloud_assets
        assert ("aws_s3", "acme-vmx-bucket") in cloud_assets
        assert ("firebase", "vagrant-firebase") in cloud_assets
        assert ("firebase", "vmx-firebase") in cloud_assets
        assert ("firebase", "vmxf-firebase") in cloud_assets
        assert ("gcs", "acme-vbox-gcs") in cloud_assets
        assert ("supabase", "vboxvault") in cloud_assets
        assert ("supabase", "vagrantvault") in cloud_assets
        assert ("supabase", "vmxvault") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[vmx_path.resolve().as_posix()]["format"] == "vmx"
        assert artifact_meta[vmx_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[vbox_path.resolve().as_posix()]["format"] == "vbox"
        assert artifact_meta[vbox_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[vagrant_path.resolve().as_posix()]["format"] == "vagrantfile"
        assert artifact_meta[vagrant_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()
