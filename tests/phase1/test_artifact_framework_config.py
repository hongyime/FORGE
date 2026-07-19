from __future__ import annotations

from textwrap import dedent

from forge.utils.artifact_framework_config import (
    framework_config_artifact_label,
    framework_config_host_candidates,
)


def test_framework_config_labels_are_source_aware() -> None:
    assert framework_config_artifact_label("config/database.yml") == "rails-database-config"
    assert framework_config_artifact_label("config/database.yaml") == "rails-database-config"
    assert framework_config_artifact_label("database.yml") == ""
    assert framework_config_artifact_label("src/main/resources/application.properties") == "spring-config"
    assert framework_config_artifact_label("offspring/application.properties") == ""
    assert framework_config_artifact_label("application.properties") == ""
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
