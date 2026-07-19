from __future__ import annotations

import pytest

from forge.utils.artifact_orm_config import (
    orm_config_artifact_label,
    orm_config_host_candidates,
)


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("schema.prisma", "prisma-schema"),
        ("prisma/schema.prisma", "prisma-schema"),
        ("prisma.config.ts", "prisma-config"),
        ("drizzle.config.ts", "drizzle-config"),
        ("ormconfig.json", "typeorm-config"),
        ("database/data-source.ts", "typeorm-config"),
        (".sequelizerc", "sequelize-config"),
        ("sequelize.config.js", "sequelize-config"),
        ("knexfile.ts", "knexfile"),
        ("mikro-orm.config.ts", "mikro-orm-config"),
        ("liquibase.properties", "liquibase-config"),
        ("liquibase/changelog.xml", "liquibase-config"),
        ("flyway.conf", "flyway-config"),
        ("schema.prisma.prisma-schema", "prisma-schema"),
    ],
)
def test_orm_config_artifact_label_recognizes_source_paths(
    value: str,
    label: str,
) -> None:
    assert orm_config_artifact_label(value) == label


@pytest.mark.parametrize(
    "value",
    [
        "config.json",
        "data-source.ts",
        "sequelize-theme.js",
        "schema.sql",
        "database/changelog.xml",
        "flyway-notes.txt",
    ],
)
def test_orm_config_artifact_label_avoids_generic_configs(value: str) -> None:
    assert orm_config_artifact_label(value) == ""


def test_orm_config_host_candidates_extracts_sanitized_hosts() -> None:
    payload = """
    datasource db {
      provider = "postgresql"
      url = "postgresql://user:password-do-not-store@prisma-db.acme.example:5432/app"
      directUrl = "postgresql://direct:direct-password-do-not-store@direct-db.acme.example:5432/app"
      shadowDatabaseUrl = env("SHADOW_DATABASE_URL")
    }
    export default {
      dbCredentials: {
        host: "drizzle-db.acme.example",
        url: "postgres://drizzle:drizzle-password-do-not-store@drizzle-url.acme.example:5432/app"
      }
    }
    {"host": "typeorm-db.acme.example", "url": "mysql://mysql-user:mysql-password-do-not-store@mysql-db.acme.example:3306/app"}
    flyway.url=jdbc:postgresql://flyway-db.acme.example:5432/app
    liquibase.command.url=jdbc:sqlserver://sqlserver-user:sqlserver-password-do-not-store@sqlserver-db.acme.example:1433;databaseName=prod
    host = "localhost"
    host = "127.0.0.1"
    host = "process.env.DB_HOST"
    """

    assert orm_config_host_candidates(payload) == [
        "prisma-db.acme.example",
        "direct-db.acme.example",
        "drizzle-db.acme.example",
        "drizzle-url.acme.example",
        "typeorm-db.acme.example",
        "mysql-db.acme.example",
        "flyway-db.acme.example",
        "sqlserver-db.acme.example",
    ]
