from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_network_dsn_hosts_without_credentials(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_network_dsns"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    env_path = artifact_root / "service.env"
    env_path.write_text(
        dedent(
            """
            DATABASE_URL=postgres://db-user:pg-password-do-not-store@db.internal.acme.example:5432/app
            MONGO_URL=mongodb+srv://mongo-user:mongo-password-do-not-store@cluster0.mongo.acme.example/app?retryWrites=true
            REDIS_URL=redis://:redis-password-do-not-store@cache.acme.example:6379/0
            AMQP_URL=amqps://mq-user:mq-password-do-not-store@mq.acme.example/prod
            JDBC_URL=jdbc:postgresql://jdbc-user:jdbc-password-do-not-store@warehouse.acme.example:5432/reporting?sslmode=require
            SQLSERVER_URL=sqlserver://sql-user:sql-password-do-not-store@sql.acme.example:1433/prod
            JDBC_SQLSERVER=jdbc:sqlserver://jdbc-sql-user:jdbc-sql-password-do-not-store@azuresql.database.windows.net:1433;databaseName=prod
            CLICKHOUSE_URL=clickhouse://click-user:click-password-do-not-store@clickhouse.acme.example:9440/default
            COUCHBASE_URL=couchbases://couch-user:couch-password-do-not-store@cb.acme.example/travel-sample
            ELASTIC_URL=elasticsearch://elastic-user:elastic-password-do-not-store@search.acme.example:9200
            LDAP_URL=ldaps://ldap-user:ldap-password-do-not-store@ldap.acme.example:636/ou=people,dc=acme,dc=example
            MEMCACHED_URL=memcached://mem-user:mem-password-do-not-store@memcached.acme.example:11211
            MQTT_URL=mqtts://mqtt-user:mqtt-password-do-not-store@mqtt.acme.example:8883
            NATS_URL=nats+tls://nats-user:nats-password-do-not-store@nats.acme.example:4222
            ORACLE_URL=oracle://oracle-user:oracle-password-do-not-store@oracle.acme.example:1521/prod
            ORACLE_JDBC=jdbc:oracle:thin:@//ora-jdbc.acme.example:1521/prod
            ORACLE_JDBC_CRED=jdbc:oracle:thin:ora-user/ora-jdbc-password-do-not-store@//ora-cred.acme.example:1521/prod
            ORACLE_JDBC_SID=jdbc:oracle:thin:@ora-sid.acme.example:1521:prod
            SNOWFLAKE_URL=snowflake://snow-user:snow-password-do-not-store@acme-account.snowflakecomputing.com/?warehouse=prod
            LOCAL_URL=postgres://local-user:local-password-do-not-store@localhost:5432/dev
            OWNER=dsn-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1

    con = sqlite3.connect(db_path)
    try:
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
        for expected_seed in {
            ("db.internal.acme.example", "subdomain"),
            ("cluster0.mongo.acme.example", "subdomain"),
            ("cache.acme.example", "subdomain"),
            ("mq.acme.example", "subdomain"),
            ("warehouse.acme.example", "subdomain"),
            ("sql.acme.example", "subdomain"),
            ("azuresql.database.windows.net", "subdomain"),
            ("clickhouse.acme.example", "subdomain"),
            ("cb.acme.example", "subdomain"),
            ("search.acme.example", "subdomain"),
            ("ldap.acme.example", "subdomain"),
            ("memcached.acme.example", "subdomain"),
            ("mqtt.acme.example", "subdomain"),
            ("nats.acme.example", "subdomain"),
            ("oracle.acme.example", "subdomain"),
            ("ora-jdbc.acme.example", "subdomain"),
            ("ora-cred.acme.example", "subdomain"),
            ("ora-sid.acme.example", "subdomain"),
            ("acme-account.snowflakecomputing.com", "subdomain"),
            ("acme.example", "domain"),
            ("dsn-owner@acme.example", "email"),
        }:
            assert expected_seed in seeds
        assert ("localhost", "domain") not in seeds
        assert ("local-password-do-not-store@localhost", "email") not in seeds

        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "dsn-owner@acme.example" in emails
        for fake_email in {
            "pg-password-do-not-store@db.internal.acme.example",
            "mongo-password-do-not-store@cluster0.mongo.acme.example",
            "redis-password-do-not-store@cache.acme.example",
            "mq-password-do-not-store@mq.acme.example",
            "jdbc-password-do-not-store@warehouse.acme.example",
            "sql-password-do-not-store@sql.acme.example",
            "jdbc-sql-password-do-not-store@azuresql.database.windows.net",
            "click-password-do-not-store@clickhouse.acme.example",
            "couch-password-do-not-store@cb.acme.example",
            "elastic-password-do-not-store@search.acme.example",
            "ldap-password-do-not-store@ldap.acme.example",
            "mem-password-do-not-store@memcached.acme.example",
            "mqtt-password-do-not-store@mqtt.acme.example",
            "nats-password-do-not-store@nats.acme.example",
            "oracle-password-do-not-store@oracle.acme.example",
            "ora-jdbc-password-do-not-store@ora-cred.acme.example",
            "snow-password-do-not-store@acme-account.snowflakecomputing.com",
            "local-password-do-not-store@localhost",
        }:
            assert fake_email not in emails

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
        assert artifact_meta[env_path.resolve().as_posix()]["format"] == "env"

        db_dump = "\n".join(con.iterdump())
        for raw_secret in {
            "pg-password-do-not-store",
            "mongo-password-do-not-store",
            "redis-password-do-not-store",
            "mq-password-do-not-store",
            "jdbc-password-do-not-store",
            "sql-password-do-not-store",
            "jdbc-sql-password-do-not-store",
            "click-password-do-not-store",
            "couch-password-do-not-store",
            "elastic-password-do-not-store",
            "ldap-password-do-not-store",
            "mem-password-do-not-store",
            "mqtt-password-do-not-store",
            "nats-password-do-not-store",
            "oracle-password-do-not-store",
            "ora-jdbc-password-do-not-store",
            "snow-password-do-not-store",
            "local-password-do-not-store",
        }:
            assert raw_secret not in db_dump
    finally:
        con.close()


def run_orm_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_orm_configs"
    prisma_dir = artifact_root / "prisma"
    database_dir = artifact_root / "database"
    prisma_dir.mkdir(parents=True)
    database_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    prisma_path = prisma_dir / "schema.prisma"
    prisma_path.write_text(
        dedent(
            """
            datasource db {
              provider = "postgresql"
              url = "postgresql://prisma:prisma-password-do-not-store@prisma-db.acme.example:5432/app"
              directUrl = "postgresql://direct:direct-password-do-not-store@direct-db.acme.example:5432/app"
              shadowDatabaseUrl = env("SHADOW_DATABASE_URL")
            }
            // owner prisma-owner@acme.example
            // firebase https://orm-firebase.firebaseio.com
            // backup s3://acme-orm-bucket/prisma/schema.prisma
            """
        ).strip(),
        encoding="utf-8",
    )

    drizzle_path = artifact_root / "drizzle.config.ts"
    drizzle_path.write_text(
        dedent(
            """
            export default {
              dbCredentials: {
                host: "drizzle-db.acme.example",
                url: "postgres://drizzle:drizzle-password-do-not-store@drizzle-url.acme.example:5432/app",
              },
              status: "https://drizzle.acme.example/status?token=hidden&view=ops",
              owner: "drizzle-owner@acme.example",
            }
            """
        ).strip(),
        encoding="utf-8",
    )

    typeorm_path = database_dir / "data-source.ts"
    typeorm_path.write_text(
        dedent(
            """
            export default new DataSource({
              type: "postgres",
              host: "typeorm-db.acme.example",
              url: "mysql://mysql:mysql-password-do-not-store@mysql-db.acme.example:3306/app",
              supportEmail: "typeorm-owner@acme.example",
            })
            """
        ).strip(),
        encoding="utf-8",
    )

    flyway_path = artifact_root / "flyway.conf"
    flyway_path.write_text(
        dedent(
            """
            flyway.url=jdbc:postgresql://flyway-db.acme.example:5432/app
            flyway.placeholders.supabase=https://ormvault.supabase.co/rest/v1
            flyway.owner=flyway-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
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
        for expected_seed in {
            ("prisma-db.acme.example", "subdomain"),
            ("direct-db.acme.example", "subdomain"),
            ("drizzle-db.acme.example", "subdomain"),
            ("drizzle-url.acme.example", "subdomain"),
            ("typeorm-db.acme.example", "subdomain"),
            ("mysql-db.acme.example", "subdomain"),
            ("flyway-db.acme.example", "subdomain"),
            ("acme.example", "domain"),
            ("prisma-owner@acme.example", "email"),
            ("drizzle-owner@acme.example", "email"),
            ("typeorm-owner@acme.example", "email"),
            ("flyway-owner@acme.example", "email"),
            ("https://drizzle.acme.example/status?view=ops", "url"),
            ("https://ormvault.supabase.co/rest/v1", "url"),
        }:
            assert expected_seed in seeds
        assert all("token=hidden" not in seed for seed, _ in seeds)

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("aws_s3", "acme-orm-bucket") in cloud_assets
        assert ("firebase", "orm-firebase") in cloud_assets
        assert ("supabase", "ormvault") in cloud_assets

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
        assert artifact_meta[prisma_path.resolve().as_posix()]["format"] == "prisma-schema"
        assert artifact_meta[drizzle_path.resolve().as_posix()]["format"] == "drizzle-config"
        assert artifact_meta[typeorm_path.resolve().as_posix()]["format"] == "typeorm-config"
        assert artifact_meta[flyway_path.resolve().as_posix()]["format"] == "flyway-config"

        db_dump = "\n".join(con.iterdump())
        for raw_secret in {
            "prisma-password-do-not-store",
            "direct-password-do-not-store",
            "drizzle-password-do-not-store",
            "mysql-password-do-not-store",
        }:
            assert raw_secret not in db_dump
    finally:
        con.close()


def run_framework_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_framework_configs"
    (artifact_root / "rails" / "config").mkdir(parents=True)
    (artifact_root / "src" / "main" / "resources").mkdir(parents=True)
    (artifact_root / "laravel" / "config").mkdir(parents=True)
    (artifact_root / "django" / "acme").mkdir(parents=True)
    bootstrap_engagement(db_path)

    rails_path = artifact_root / "rails" / "config" / "database.yml"
    rails_path.write_text(
        dedent(
            """
            production:
              host: rails-db.acme.example
              database: acme
              password: rails-password-do-not-store
            # owner rails-owner@acme.example
            # firebase https://framework-firebase.firebaseio.com
            """
        ).strip(),
        encoding="utf-8",
    )

    spring_path = artifact_root / "src" / "main" / "resources" / "application.properties"
    spring_path.write_text(
        dedent(
            """
            spring.datasource.url=jdbc:postgresql://spring:spring-password-do-not-store@spring-db.acme.example:5432/app
            support.email=spring-owner@acme.example
            supabase.url=https://frameworkworkspace.supabase.co/rest/v1
            """
        ).strip(),
        encoding="utf-8",
    )

    dotnet_path = artifact_root / "appsettings.Production.json"
    dotnet_path.write_text(
        json.dumps(
            {
                "ConnectionStrings": {
                    "DefaultConnection": "Server=tcp:dotnet-db.acme.example,1433;Database=Forge;Password=dotnet-password-do-not-store"
                },
                "Owner": "dotnet-owner@acme.example",
                "Archive": "s3://acme-framework-bucket/appsettings.json",
            }
        ),
        encoding="utf-8",
    )

    alembic_path = artifact_root / "alembic.ini"
    alembic_path.write_text(
        "sqlalchemy.url = mysql://alembic:alembic-password-do-not-store@alembic-db.acme.example:3306/app\n",
        encoding="utf-8",
    )

    laravel_path = artifact_root / "laravel" / "config" / "database.php"
    laravel_path.write_text(
        dedent(
            """
            <?php
            return [
              'host' => env('DB_HOST', 'laravel-db.acme.example'),
              'url' => env('DATABASE_URL', 'postgres://laravel:laravel-password-do-not-store@laravel-url-db.acme.example:5432/app'),
              'owner' => 'laravel-owner@acme.example',
            ];
            """
        ).strip(),
        encoding="utf-8",
    )

    django_path = artifact_root / "django" / "acme" / "settings.py"
    django_path.write_text(
        dedent(
            """
            DATABASES = {'default': {'HOST': 'django-db.acme.example'}}
            ADMIN_EMAIL = "django-owner@acme.example"
            GCS_BACKUP = "gs://acme-framework-gcs/settings.py"
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 6
    assert summary.processed >= 6
    assert summary.discovered_seeds >= 14

    con = sqlite3.connect(db_path)
    try:
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
        for expected_seed in {
            ("rails-db.acme.example", "subdomain"),
            ("spring-db.acme.example", "subdomain"),
            ("dotnet-db.acme.example", "subdomain"),
            ("alembic-db.acme.example", "subdomain"),
            ("laravel-db.acme.example", "subdomain"),
            ("laravel-url-db.acme.example", "subdomain"),
            ("django-db.acme.example", "subdomain"),
            ("rails-owner@acme.example", "email"),
            ("spring-owner@acme.example", "email"),
            ("dotnet-owner@acme.example", "email"),
            ("laravel-owner@acme.example", "email"),
            ("django-owner@acme.example", "email"),
            ("https://frameworkworkspace.supabase.co/rest/v1", "url"),
        }:
            assert expected_seed in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("aws_s3", "acme-framework-bucket") in cloud_assets
        assert ("firebase", "framework-firebase") in cloud_assets
        assert ("gcs", "acme-framework-gcs") in cloud_assets
        assert ("supabase", "frameworkworkspace") in cloud_assets

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
        assert artifact_meta[rails_path.resolve().as_posix()]["format"] == "rails-database-config"
        assert artifact_meta[spring_path.resolve().as_posix()]["format"] == "spring-config"
        assert artifact_meta[dotnet_path.resolve().as_posix()]["format"] == "dotnet-appsettings"
        assert artifact_meta[alembic_path.resolve().as_posix()]["format"] == "alembic-config"
        assert (
            artifact_meta[laravel_path.resolve().as_posix()]["format"] == "laravel-database-config"
        )
        assert artifact_meta[django_path.resolve().as_posix()]["format"] == "django-settings"

        db_dump = "\n".join(con.iterdump())
        for raw_secret in {
            "rails-password-do-not-store",
            "spring-password-do-not-store",
            "dotnet-password-do-not-store",
            "alembic-password-do-not-store",
            "laravel-password-do-not-store",
        }:
            assert raw_secret not in db_dump
    finally:
        con.close()
