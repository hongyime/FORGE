from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_diagram_design_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_diagrams"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    drawio_path = artifact_root / "architecture.drawio"
    drawio_path.write_text(
        dedent(
            """
            <mxfile>
              <diagram name="Cloud">
                <mxGraphModel>
                  <root>
                    <mxCell value="owner drawio-owner@acme.example https://drawio.acme.example/app https://drawio-firebase.firebaseio.com" />
                  </root>
                </mxGraphModel>
              </diagram>
            </mxfile>
            """
        ).strip(),
        encoding="utf-8",
    )

    excalidraw_path = artifact_root / "incident.excalidraw"
    excalidraw_path.write_text(
        json.dumps(
            {
                "type": "excalidraw",
                "elements": [
                    {
                        "type": "text",
                        "text": (
                            "excalidraw-owner@acme.example "
                            "https://excalidraw.acme.example/runbook "
                            "https://excalidrawvault.supabase.co/rest/v1"
                        ),
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    mermaid_path = artifact_root / "attack-path.mmd"
    mermaid_path.write_text(
        dedent(
            """
            graph TD
              A[mermaid-owner@acme.example] --> B[https://mermaid.acme.example/status]
              B --> C[s3://acme-mermaid-bucket/exports/latest.json]
            """
        ).strip(),
        encoding="utf-8",
    )

    plantuml_path = artifact_root / "sequence.puml"
    plantuml_path.write_text(
        dedent(
            """
            @startuml
            actor "plantuml-owner@acme.example"
            participant "https://plantuml.acme.example/api"
            note right: gs://acme-plantuml-gcs/diagrams/latest.txt
            @enduml
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "diagram-bundle.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "nested/flow.mermaid",
            dedent(
                """
                sequenceDiagram
                  participant Owner as nested-diagram-owner@acme.example
                  Owner->>API: https://nested-diagram.acme.example/callback
                  API->>Cloud: https://nested-diagram-firebase.firebaseio.com
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 5
    assert summary.processed >= 5
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "drawio-owner@acme.example",
            "excalidraw-owner@acme.example",
            "mermaid-owner@acme.example",
            "plantuml-owner@acme.example",
            "nested-diagram-owner@acme.example",
        }:
            assert expected_email in emails

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
        for expected_url in {
            "https://drawio.acme.example/app",
            "https://excalidraw.acme.example/runbook",
            "https://mermaid.acme.example/status",
            "https://plantuml.acme.example/api",
            "https://nested-diagram.acme.example/callback",
        }:
            assert (expected_url, "url") in seeds
        assert ("drawio-owner@acme.example", "email") in seeds
        assert ("nested-diagram-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-mermaid-bucket") in cloud_assets
        assert ("firebase", "drawio-firebase") in cloud_assets
        assert ("firebase", "nested-diagram-firebase") in cloud_assets
        assert ("gcs", "acme-plantuml-gcs") in cloud_assets
        assert ("supabase", "excalidrawvault") in cloud_assets

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
        assert artifact_meta[drawio_path.resolve().as_posix()]["format"] == "drawio"
        assert artifact_meta[excalidraw_path.resolve().as_posix()]["format"] == "excalidraw"
        assert artifact_meta[mermaid_path.resolve().as_posix()]["format"] == "mmd"
        assert artifact_meta[plantuml_path.resolve().as_posix()]["format"] == "puml"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_apple_resource_metadata_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_apple_resources"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    storyboard_path = artifact_root / "Main.storyboard"
    storyboard_path.write_text(
        dedent(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <document type="com.apple.InterfaceBuilder3.CocoaTouch.Storyboard">
              <objects>
                <label text="storyboard-owner@acme.example" />
                <button userLabel="https://storyboard.acme.example/start" />
                <userDefinedRuntimeAttribute keyPath="firebase" value="https://storyboard-firebase.firebaseio.com" />
                <userDefinedRuntimeAttribute keyPath="supabase" value="https://storyboardvault.supabase.co/rest/v1" />
              </objects>
            </document>
            """
        ).strip(),
        encoding="utf-8",
    )

    privacy_path = artifact_root / "PrivacyInfo.xcprivacy"
    privacy_path.write_text(
        dedent(
            """
            {
              "NSPrivacyTrackingDomains": [
                "privacy-owner@acme.example",
                "https://privacy.acme.example/tracking",
                "s3://acme-privacy-bucket/privacy/latest.json"
              ]
            }
            """
        ).strip(),
        encoding="utf-8",
    )

    string_catalog_path = artifact_root / "Localizable.xcstrings"
    string_catalog_path.write_text(
        dedent(
            """
            {
              "strings": {
                "support": {"localizations": {"en": {"stringUnit": {"value": "strings-owner@acme.example"}}}},
                "portal": {"localizations": {"en": {"stringUnit": {"value": "https://strings.acme.example/help"}}}},
                "archive": {"localizations": {"en": {"stringUnit": {"value": "gs://acme-strings-gcs/help/latest.json"}}}}
              }
            }
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "apple-resources.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "Base.lproj/Login.xib",
            dedent(
                """
                <?xml version="1.0" encoding="UTF-8"?>
                <document type="com.apple.InterfaceBuilder3.CocoaTouch.XIB">
                  <objects>
                    <textField placeholder="xib-owner@acme.example" />
                    <button title="https://xib.acme.example/login" />
                    <userDefinedRuntimeAttribute keyPath="firebase" value="https://xib-firebase.firebaseio.com" />
                  </objects>
                </document>
                """
            ).strip(),
        )
        zf.writestr(
            "Base.lproj/Localizable.stringsdict",
            dedent(
                """
                <plist version="1.0">
                <dict>
                  <key>Owner</key><string>stringsdict-owner@acme.example</string>
                  <key>Portal</key><string>https://stringsdict.acme.example/localized</string>
                  <key>Supabase</key><string>https://stringsdictvault.supabase.co/rest/v1</string>
                </dict>
                </plist>
                """
            ).strip(),
        )
        zf.writestr(
            "Images.xcassets/AppIcon.appiconset/Contents.json",
            dedent(
                """
                {
                  "info": {"author": "asset-owner@acme.example", "version": 1},
                  "properties": {
                    "template-rendering-intent": "https://assets.acme.example/icon",
                    "storage": "s3://acme-assets-bucket/icons/latest.png"
                  }
                }
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 14

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "storyboard-owner@acme.example",
            "privacy-owner@acme.example",
            "strings-owner@acme.example",
            "xib-owner@acme.example",
            "stringsdict-owner@acme.example",
            "asset-owner@acme.example",
        }:
            assert expected_email in emails

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
        for expected_url in {
            "https://storyboard.acme.example/start",
            "https://privacy.acme.example/tracking",
            "https://strings.acme.example/help",
            "https://xib.acme.example/login",
            "https://stringsdict.acme.example/localized",
            "https://assets.acme.example/icon",
        }:
            assert (expected_url, "url") in seeds
        assert ("storyboard-owner@acme.example", "email") in seeds
        assert ("xib-owner@acme.example", "email") in seeds
        assert ("asset-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-assets-bucket") in cloud_assets
        assert ("aws_s3", "acme-privacy-bucket") in cloud_assets
        assert ("firebase", "storyboard-firebase") in cloud_assets
        assert ("firebase", "xib-firebase") in cloud_assets
        assert ("gcs", "acme-strings-gcs") in cloud_assets
        assert ("supabase", "storyboardvault") in cloud_assets
        assert ("supabase", "stringsdictvault") in cloud_assets

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
        assert artifact_meta[storyboard_path.resolve().as_posix()]["format"] == "storyboard"
        assert artifact_meta[privacy_path.resolve().as_posix()]["format"] == "xcprivacy"
        assert artifact_meta[string_catalog_path.resolve().as_posix()]["format"] == "xcstrings"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 3
    finally:
        con.close()


def run_game_engine_metadata_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_game_engine"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    unity_scene_path = artifact_root / "Main.unity"
    unity_scene_path.write_text(
        dedent(
            """
            %YAML 1.1
            --- !u!1 &100000
            GameObject:
              m_Name: AcmeNetworkBootstrap
              m_TagString: unity-owner@acme.example
              m_EditorClassIdentifier: https://unity.acme.example/scene
              firebaseDatabaseUrl: https://unity-firebase.firebaseio.com
              supabaseApi: https://unityvault.supabase.co/rest/v1
            """
        ).strip(),
        encoding="utf-8",
    )

    asmdef_path = artifact_root / "Acme.Runtime.asmdef"
    asmdef_path.write_text(
        dedent(
            """
            {
              "name": "Acme.Runtime",
              "owner": "asmdef-owner@acme.example",
              "documentationUrl": "https://asmdef.acme.example/runtime",
              "releaseManifest": "s3://acme-asmdef-bucket/runtime/latest.json"
            }
            """
        ).strip(),
        encoding="utf-8",
    )

    unreal_project_path = artifact_root / "AcmeGame.uproject"
    unreal_project_path.write_text(
        dedent(
            """
            {
              "FileVersion": 3,
              "EngineAssociation": "5.4",
              "Owner": "uproject-owner@acme.example",
              "Homepage": "https://uproject.acme.example/game",
              "BuildArtifact": "gs://acme-uproject-gcs/game/latest.json"
            }
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "game-engine-metadata.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "Assets/Player.prefab",
            dedent(
                """
                %YAML 1.1
                --- !u!1 &200000
                GameObject:
                  m_Name: PlayerNetworkProfile
                  m_TagString: prefab-owner@acme.example
                  m_EditorClassIdentifier: https://prefab.acme.example/player
                  archive: s3://acme-prefab-bucket/player/latest.prefab
                """
            ).strip(),
        )
        zf.writestr(
            "Assets/Shaders/Network.shader",
            dedent(
                """
                Shader "Acme/Network"
                {
                  // owner shader-owner@acme.example
                  // endpoint https://shader.acme.example/render
                  // firebase https://shader-firebase.firebaseio.com
                  SubShader { Pass {} }
                }
                """
            ).strip(),
        )
        zf.writestr(
            "Assets/Shaders/PostProcess.hlsl",
            dedent(
                """
                // owner hlsl-owner@acme.example
                // render endpoint https://hlsl.acme.example/render
                // firebase https://hlsl-firebase.firebaseio.com
                float4 main() : SV_Target { return float4(1, 1, 1, 1); }
                """
            ).strip(),
        )
        zf.writestr(
            "Plugins/Acme.uplugin",
            dedent(
                """
                {
                  "FileVersion": 3,
                  "FriendlyName": "Acme",
                  "Owner": "uplugin-owner@acme.example",
                  "DocsURL": "https://uplugin.acme.example/docs",
                  "Supabase": "https://upluginvault.supabase.co/rest/v1"
                }
                """
            ).strip(),
        )
        zf.writestr(
            "Shaders/Common.ush",
            dedent(
                """
                // owner ush-owner@acme.example
                // shared shader docs https://ush.acme.example/shader
                // gcs mirror gs://acme-ush-gcs/shaders/latest.ush
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 16

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "unity-owner@acme.example",
            "asmdef-owner@acme.example",
            "uproject-owner@acme.example",
            "prefab-owner@acme.example",
            "shader-owner@acme.example",
            "hlsl-owner@acme.example",
            "uplugin-owner@acme.example",
            "ush-owner@acme.example",
        }:
            assert expected_email in emails

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
        for expected_url in {
            "https://unity.acme.example/scene",
            "https://asmdef.acme.example/runtime",
            "https://uproject.acme.example/game",
            "https://prefab.acme.example/player",
            "https://shader.acme.example/render",
            "https://hlsl.acme.example/render",
            "https://uplugin.acme.example/docs",
            "https://ush.acme.example/shader",
        }:
            assert (expected_url, "url") in seeds
        assert ("unity-owner@acme.example", "email") in seeds
        assert ("hlsl-owner@acme.example", "email") in seeds
        assert ("uplugin-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-asmdef-bucket") in cloud_assets
        assert ("aws_s3", "acme-prefab-bucket") in cloud_assets
        assert ("firebase", "hlsl-firebase") in cloud_assets
        assert ("firebase", "shader-firebase") in cloud_assets
        assert ("firebase", "unity-firebase") in cloud_assets
        assert ("gcs", "acme-uproject-gcs") in cloud_assets
        assert ("gcs", "acme-ush-gcs") in cloud_assets
        assert ("supabase", "unityvault") in cloud_assets
        assert ("supabase", "upluginvault") in cloud_assets

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
        assert artifact_meta[unity_scene_path.resolve().as_posix()]["format"] == "unity"
        assert artifact_meta[asmdef_path.resolve().as_posix()]["format"] == "asmdef"
        assert artifact_meta[unreal_project_path.resolve().as_posix()]["format"] == "uproject"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 5
    finally:
        con.close()
