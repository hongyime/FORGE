from __future__ import annotations

import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_framework_config import (
    framework_config_artifact_label,
    framework_config_host_candidates,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_framework_config_labels_are_source_aware() -> None:
    assert framework_config_artifact_label("config/database.yml") == "rails-database-config"
    assert framework_config_artifact_label("config/database.yaml") == "rails-database-config"
    assert framework_config_artifact_label("database.yml") == ""
    assert framework_config_artifact_label("src/main/resources/application.properties") == "spring-config"
    assert framework_config_artifact_label("src/main/resources/application-prod.yml") == "spring-config"
    assert framework_config_artifact_label("src/main/resources/bootstrap-prod.properties") == "spring-config"
    assert framework_config_artifact_label("spring/application-local.yaml") == "spring-config"
    assert framework_config_artifact_label("offspring/application.properties") == ""
    assert framework_config_artifact_label("offspring/application-prod.yml") == ""
    assert framework_config_artifact_label("application.properties") == ""
    assert framework_config_artifact_label("application-prod.yml") == ""
    assert framework_config_artifact_label("appsettings.Production.json") == "dotnet-appsettings"
    assert framework_config_artifact_label("web.config") == "dotnet-web-config"
    assert framework_config_artifact_label("alembic.ini") == "alembic-config"
    assert framework_config_artifact_label("laravel/config/database.php") == "laravel-database-config"
    assert framework_config_artifact_label("django/acme/settings.py") == "django-settings"
    assert framework_config_artifact_label("djangonaut/settings.py") == ""
    assert framework_config_artifact_label("settings.py") == ""
    assert framework_config_artifact_label("database.yml.rails-database-config") == "rails-database-config"


def test_framework_config_host_candidates_strip_credentials_and_templates() -> None:
    text = dedent(
        """
        production:
          host: rails-db.acme.example
          database: app_production
          username: rails
          password: rails-password-do-not-store
        spring.datasource.url=jdbc:postgresql://spring:spring-password-do-not-store@spring-db.acme.example:5432/app
        sqlalchemy.url = mysql://alembic:alembic-password-do-not-store@alembic-db.acme.example:3306/app
        "DefaultConnection": "Server=tcp:dotnet-db.acme.example,1433;Database=Forge;User Id=forge;Password=dotnet-password-do-not-store"
        <add name="Main" connectionString="Host=webconfig-db.acme.example;Port=5432;Password=web-password-do-not-store" />
        'host' => env('DB_HOST', 'laravel-db.acme.example'),
        DATABASES = {'default': {'HOST': 'django-db.acme.example'}}
        ignored_host = "${DB_HOST}"
        local: localhost
        """
    )

    assert framework_config_host_candidates(text) == [
        "rails-db.acme.example",
        "spring-db.acme.example",
        "alembic-db.acme.example",
        "dotnet-db.acme.example",
        "webconfig-db.acme.example",
        "laravel-db.acme.example",
        "django-db.acme.example",
    ]


def test_spring_profile_configs_feed_framework_hosts_into_recursive_seeds(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_spring_profiles" / "src" / "main" / "resources"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path)

    (artifact_root / "application-prod.yml").write_text(
        dedent(
            """
            spring.datasource.url: jdbc:postgresql://prod:prod-password-do-not-store@spring-profile-db.acme.example:5432/app
            ignored.host: ${DB_HOST}
            """
        ).strip(),
        encoding="utf-8",
    )
    (artifact_root / "bootstrap-prod.properties").write_text(
        "spring.datasource.jdbc-url=jdbc:mysql://boot:boot-password-do-not-store@spring-bootstrap-db.acme.example:3306/app\n",
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=2)
    queued = processor.ingest_local_artifacts([artifact_root.parent.parent.parent])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            tuple(row)
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            )
        }
        assert ("spring-profile-db.acme.example", "subdomain") in seeds
        assert ("spring-bootstrap-db.acme.example", "subdomain") in seeds

        artifact_meta = {
            row[0]: row[1]
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            )
        }
        assert "spring-config" in artifact_meta[(artifact_root / "application-prod.yml").resolve().as_posix()]
        assert "spring-config" in artifact_meta[
            (artifact_root / "bootstrap-prod.properties").resolve().as_posix()
        ]

        db_dump = "\n".join(con.iterdump())
        assert "prod-password-do-not-store" not in db_dump
        assert "boot-password-do-not-store" not in db_dump
        assert "${DB_HOST}" not in db_dump
    finally:
        con.close()
