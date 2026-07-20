from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def _process_artifacts(db_path: Path, artifact_root: Path):
    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    return queued, processor.process()


def _seed_pairs(db_path: Path) -> set[tuple[str, str]]:
    con = sqlite3.connect(db_path)
    try:
        return {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()


def _cloud_assets(db_path: Path) -> list[tuple[str, str]]:
    con = sqlite3.connect(db_path)
    try:
        return con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
    finally:
        con.close()


def _artifact_meta(db_path: Path) -> dict[str, dict[str, object]]:
    con = sqlite3.connect(db_path)
    try:
        return {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()


def _emails(db_path: Path) -> set[str]:
    con = sqlite3.connect(db_path)
    try:
        return {
            row[0]
            for row in con.execute(
                "SELECT email FROM emails WHERE engagement_id=1001"
            ).fetchall()
        }
    finally:
        con.close()


def run_codebuild_buildspec_secret_refs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_codebuild_buildspec"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json=(
            '["*.acme.example","+15551234567","security@acme.example",'
            '"https://downloads.acme.example/app.apk"]'
        ),
        operator="delta-one",
    )

    buildspec_path = artifact_root / "buildspec.yml"
    buildspec_path.write_text(
        dedent(
            """
            version: 0.2
            env:
              variables:
                OWNER_EMAIL: codebuild-owner@acme.example
                STATUS_URL: https://codebuild.acme.example/report
                FIREBASE_URL: https://codebuild-firebase.firebaseio.com
                ARTIFACT_BUCKET: s3://acme-codebuild-artifacts/reports/latest.json
              parameter-store:
                DOCKER_PASSWORD: /CodeBuild/dockerLoginPassword
              secrets-manager:
                DB_PASSWORD: prod/db/password:password
                API_KEY: arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key-AbCdEf:token
            phases:
              pre_build:
                commands:
                  - docker pull public.ecr.aws/docker/library/alpine:latest
              build:
                commands:
                  - curl https://codebuild.acme.example/status
            artifacts:
              files:
                - '**/*'
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.discovered_seeds >= 4

    seeds = _seed_pairs(db_path)
    assert ("codebuild-owner@acme.example", "email") in seeds
    assert ("https://codebuild.acme.example/report", "url") in seeds
    assert ("https://codebuild.acme.example/status", "url") in seeds
    assert ("https://public.ecr.aws/docker/library/alpine", "url") in seeds

    cloud_assets = _cloud_assets(db_path)
    assert ("aws_parameterstore", "codebuild/dockerloginpassword") in cloud_assets
    assert (
        "aws_secretsmanager",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key-abcdef",
    ) in cloud_assets
    assert ("aws_secretsmanager", "prod/db/password") in cloud_assets
    assert ("aws_s3", "acme-codebuild-artifacts") in cloud_assets
    assert ("firebase", "codebuild-firebase") in cloud_assets

    artifact_meta = _artifact_meta(db_path)
    assert artifact_meta[buildspec_path.resolve().as_posix()]["format"] == "codebuild-buildspec"


def run_ci_cd_workflow_metadata_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_ci_cd_workflows"
    artifact_root.mkdir()
    github_workflows = artifact_root / ".github" / "workflows"
    github_workflows.mkdir(parents=True)
    circleci_dir = artifact_root / ".circleci"
    circleci_dir.mkdir()
    buildkite_dir = artifact_root / ".buildkite"
    buildkite_dir.mkdir()
    bootstrap_engagement(db_path)

    gitlab_path = artifact_root / "gitlab-ci"
    gitlab_path.write_text(
        dedent(
            """
            stages: [deploy]
            deploy:
              variables:
                OWNER_EMAIL: gitlab-owner@acme.example
                STATUS_URL: https://gitlab-ci.acme.example/deploy
                FIREBASE_URL: https://gitlab-ci-firebase.firebaseio.com
                RELEASE_BUCKET: s3://acme-gitlab-ci-bucket/releases/latest.json
            """
        ).strip(),
        encoding="utf-8",
    )

    github_path = github_workflows / "deploy.yml"
    github_path.write_text(
        dedent(
            """
            name: deploy
            on: [push]
            jobs:
              deploy:
                runs-on: ubuntu-latest
                env:
                  OWNER_EMAIL: github-actions-owner@acme.example
                  STATUS_URL: https://github-actions.acme.example/deploy
                  SUPABASE_URL: https://gha-workspace.supabase.co/rest/v1
                  ARCHIVE_URI: gs://acme-github-actions-gcs/releases/latest.json
                steps:
                  - uses: actions/setup-python@v5
                  - uses: docker://ghcr.io/acme/workflow-helper:latest
              reuse:
                uses: acme/shared-actions/.github/workflows/deploy.yml@v2
                with:
                  environment: prod
            """
        ).strip(),
        encoding="utf-8",
    )

    cloudbuild_path = artifact_root / "cloudbuild.yaml"
    cloudbuild_path.write_text(
        dedent(
            """
            steps:
              - name: gcr.io/cloud-builders/gcloud
                args: ["deploy"]
            images:
              - gcr.io/acme/cloudbuild-output:latest
            artifacts:
              images:
                - us-docker.pkg.dev/acme/prod/cloudbuild-api:sha
            logsBucket: gs://acme-cloudbuild-logs/builds
            substitutions:
              _OWNER: cloudbuild-owner@acme.example
              _PORTAL: https://cloudbuild.acme.example/status
              _AZURE: https://cloudbuildblob.blob.core.windows.net/public/build.json
            """
        ).strip(),
        encoding="utf-8",
    )

    taskfile_path = artifact_root / "Taskfile"
    taskfile_path.write_text(
        dedent(
            """
            version: '3'
            vars:
              OWNER: taskfile-owner@acme.example
              DASHBOARD: https://taskfile.acme.example/tasks
              FIREBASE: https://taskfile-firebase.firebaseio.com
            tasks:
              deploy:
                cmds:
                  - echo deploy
            """
        ).strip(),
        encoding="utf-8",
    )

    circleci_path = circleci_dir / "config.yml"
    circleci_path.write_text(
        dedent(
            """
            version: 2.1
            executors:
              release:
                docker:
                  - image: registry.circleci.acme.example/build/release-runner:1.0
            jobs:
              deploy:
                docker:
                  - image: cimg/base:stable
                  - image: ghcr.io/acme/circleci-runner:2026.07
                environment:
                  OWNER_EMAIL: circleci-owner@acme.example
                  STATUS_URL: https://circleci.acme.example/pipeline
                  SUPABASE_URL: https://circlecivault.supabase.co/rest/v1
            workflows:
              deploy:
                jobs:
                  - deploy
            """
        ).strip(),
        encoding="utf-8",
    )

    drone_path = artifact_root / ".drone.yml"
    drone_path.write_text(
        dedent(
            """
            kind: pipeline
            type: docker
            name: default
            steps:
              - name: deploy
                image: ghcr.io/acme/drone-deployer:1.2
            """
        ).strip(),
        encoding="utf-8",
    )

    buildkite_path = buildkite_dir / "pipeline.yml"
    buildkite_path.write_text(
        dedent(
            """
            name: deploy
            steps:
              - label: ":rocket:"
                command: deploy
                plugins:
                  - docker#v5.11.0:
                      image: ghcr.io/acme/buildkite-runner:latest
            """
        ).strip(),
        encoding="utf-8",
    )

    woodpecker_path = artifact_root / ".woodpecker.yml"
    woodpecker_path.write_text(
        dedent(
            """
            pipeline:
              deploy:
                image: registry.woodpecker.acme.example/ci/deploy:latest
                commands:
                  - deploy
            """
        ).strip(),
        encoding="utf-8",
    )

    appveyor_path = artifact_root / "appveyor.yml"
    appveyor_path.write_text(
        dedent(
            """
            environment:
              OWNER_EMAIL: appveyor-owner@acme.example
              STATUS_URL: https://appveyor.acme.example/build
              FIREBASE_URL: https://appveyor-firebase.firebaseio.com
            build_script:
              - echo build
            """
        ).strip(),
        encoding="utf-8",
    )

    tekton_path = artifact_root / "pipelinerun.yaml"
    tekton_path.write_text(
        dedent(
            """
            apiVersion: tekton.dev/v1beta1
            kind: PipelineRun
            metadata:
              name: deploy-run
              namespace: ci
            spec:
              pipelineRef:
                name: deploy-pipeline
              params:
                - name: repo-url
                  value: https://github.com/acme/tekton-configs.git
              workspaces:
                - name: output
                  configMap:
                    name: tekton-owner-acme-example
              taskRunTemplate:
                serviceAccountName: tekton-runner
            """
        ).strip(),
        encoding="utf-8",
    )

    argo_workflow_path = artifact_root / "workflow.yaml"
    argo_workflow_path.write_text(
        dedent(
            """
            apiVersion: argoproj.io/v1alpha1
            kind: Workflow
            metadata:
              name: wf-deploy
              namespace: argo
            spec:
              entrypoint: deploy
              templates:
                - name: deploy
                  container:
                    image: ghcr.io/acme/workflow-runner:latest
                    env:
                      - name: REPORT_BUCKET
                        value: s3://acme-argo-workflow-bucket/reports/latest.json
                      - name: CALLBACK_URL
                        value: https://argo-workflows.acme.example/status
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "ci-workflows.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "bitbucket-pipelines",
            """
            pipelines:
              default:
                - step:
                    script:
                      - echo bitbucket-owner@acme.example
                      - curl https://bitbucket-pipelines.acme.example/build
                      - echo s3://acme-bitbucket-pipelines-bucket/build/latest.json
            """.strip(),
        )
        zf.writestr(
            ".drone.yml",
            """
            kind: pipeline
            type: docker
            name: default
            steps:
              - name: deploy
                image: ghcr.io/acme/drone-deployer:1.2
            environment:
              OWNER_EMAIL: drone-owner@acme.example
              STATUS_URL: https://drone.acme.example/build
              FIREBASE_URL: https://drone-firebase.firebaseio.com
            """.strip(),
        )
        zf.writestr(
            ".buildkite/pipeline.yml",
            """
            name: deploy
            steps:
              - label: ":rocket:"
                command: deploy
                plugins:
                  - docker#v5.11.0:
                      image: ghcr.io/acme/buildkite-runner:latest
                env:
                  OWNER_EMAIL: buildkite-owner@acme.example
                  STATUS_URL: https://buildkite.acme.example/pipeline
                  GCS_ARCHIVE: gs://acme-buildkite-gcs/pipelines/latest.json
            """.strip(),
        )
        zf.writestr(
            ".woodpecker.yml",
            """
            pipeline:
              deploy:
                image: registry.woodpecker.acme.example/ci/deploy:latest
                commands:
                  - echo woodpecker-owner@acme.example
                  - echo https://woodpecker.acme.example/pipeline
                  - echo https://woodpeckervault.supabase.co/rest/v1
            """.strip(),
        )
        zf.writestr(
            "appveyor.yml",
            """
            environment:
              OWNER_EMAIL: appveyor-owner@acme.example
              STATUS_URL: https://appveyor.acme.example/build
              FIREBASE_URL: https://appveyor-firebase.firebaseio.com
            build_script:
              - echo build
            """.strip(),
        )

    queued, summary = _process_artifacts(db_path, artifact_root)

    assert queued >= 8
    assert summary.processed >= 8
    assert summary.firebase_projects >= 4
    assert summary.discovered_seeds >= 22

    for expected_email in {
        "gitlab-owner@acme.example",
        "github-actions-owner@acme.example",
        "cloudbuild-owner@acme.example",
        "taskfile-owner@acme.example",
        "circleci-owner@acme.example",
        "bitbucket-owner@acme.example",
        "drone-owner@acme.example",
        "buildkite-owner@acme.example",
        "woodpecker-owner@acme.example",
        "appveyor-owner@acme.example",
    }:
        assert expected_email in _emails(db_path)

    seeds = _seed_pairs(db_path)
    for expected_url in {
        "https://gitlab-ci.acme.example/deploy",
        "https://github-actions.acme.example/deploy",
        "https://github.com/acme/shared-actions",
        "https://github.com/acme/tekton-configs",
        "https://github.com/actions/setup-python",
        "https://ghcr.io/acme/workflow-helper",
        "https://ghcr.io/acme/workflow-runner",
        "https://gcr.io/acme/cloudbuild-output",
        "https://gcr.io/cloud-builders/gcloud",
        "https://us-docker.pkg.dev/acme/prod/cloudbuild-api",
        "https://cloudbuild.acme.example/status",
        "https://ghcr.io/acme/circleci-runner",
        "https://registry.circleci.acme.example/build/release-runner",
        "https://taskfile.acme.example/tasks",
        "https://circleci.acme.example/pipeline",
        "https://bitbucket-pipelines.acme.example/build",
        "https://drone.acme.example/build",
        "https://ghcr.io/acme/drone-deployer",
        "https://buildkite.acme.example/pipeline",
        "https://ghcr.io/acme/buildkite-runner",
        "https://woodpecker.acme.example/pipeline",
        "https://registry.woodpecker.acme.example/ci/deploy",
        "https://appveyor.acme.example/build",
        "https://argo-workflows.acme.example/status",
    }:
        assert (expected_url, "url") in seeds
    assert ("gitlab-owner@acme.example", "email") in seeds
    assert ("github-actions-owner@acme.example", "email") in seeds
    assert ("appveyor-owner@acme.example", "email") in seeds

    cloud_assets = _cloud_assets(db_path)
    for expected_asset in {
        ("aws_s3", "acme-bitbucket-pipelines-bucket"),
        ("aws_s3", "acme-argo-workflow-bucket"),
        ("aws_s3", "acme-gitlab-ci-bucket"),
        ("argo_workflow", "argo/wf-deploy"),
        ("azure_blob", "cloudbuildblob/public"),
        ("appveyor_pipeline", "pipeline"),
        ("buildkite_pipeline", "deploy"),
        ("circleci_pipeline", "deploy"),
        ("drone_pipeline", "default"),
        ("firebase", "appveyor-firebase"),
        ("firebase", "drone-firebase"),
        ("firebase", "gitlab-ci-firebase"),
        ("firebase", "taskfile-firebase"),
        ("gcs", "acme-buildkite-gcs"),
        ("gcs", "acme-cloudbuild-logs"),
        ("gcs", "acme-github-actions-gcs"),
        ("github_action", "acme/shared-actions/.github/workflows/deploy.yml"),
        ("github_action", "actions/setup-python"),
        ("github_workflow", "deploy"),
        ("supabase", "circlecivault"),
        ("supabase", "gha-workspace"),
        ("supabase", "woodpeckervault"),
        ("tekton_pipelinerun", "ci/deploy-run"),
        ("woodpecker_pipeline", "pipeline"),
    }:
        assert expected_asset in cloud_assets

    artifact_meta = _artifact_meta(db_path)
    assert artifact_meta[gitlab_path.resolve().as_posix()]["format"] == "gitlab-ci"
    assert artifact_meta[github_path.resolve().as_posix()]["format"] == "github-actions-workflow"
    assert artifact_meta[cloudbuild_path.resolve().as_posix()]["format"] == "cloudbuild"
    assert artifact_meta[taskfile_path.resolve().as_posix()]["format"] == "taskfile"
    assert artifact_meta[circleci_path.resolve().as_posix()]["format"] == "circleci"
    assert artifact_meta[drone_path.resolve().as_posix()]["format"] == "drone"
    assert artifact_meta[buildkite_path.resolve().as_posix()]["format"] == "buildkite"
    assert artifact_meta[woodpecker_path.resolve().as_posix()]["format"] == "woodpecker"
    assert artifact_meta[appveyor_path.resolve().as_posix()]["format"] == "appveyor"
    assert artifact_meta[tekton_path.resolve().as_posix()]["format"] == "tekton-pipelinerun"
    assert artifact_meta[argo_workflow_path.resolve().as_posix()]["format"] == "argo-workflow"
    assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
    assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 5


def run_bitbucket_pipelines_resource_refs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_bitbucket_pipelines"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    bitbucket_path = artifact_root / "bitbucket-pipelines.yml"
    bitbucket_path.write_text(
        dedent(
            """
            name: deploy-prod
            image: ghcr.io/acme/bitbucket-runner:latest
            definitions:
              repositories:
                shared:
                  url: https://bitbucket.org/acme/pipeline-templates.git
                infra: acme/infra-scripts
              services:
                scanner:
                  image: registry.gitlab.com/acme/ci-scanner:2.1
            pipelines:
              default:
                - step:
                    name: Deploy
                    script:
                      - echo bitbucket-owner@acme.example
                      - curl https://bitbucket-pipelines.acme.example/build
                      - echo s3://acme-bitbucket-pipelines-bucket/build/latest.json
            """
        ).strip(),
        encoding="utf-8",
    )

    queued, summary = _process_artifacts(db_path, artifact_root)

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 5

    seeds = _seed_pairs(db_path)
    assert ("bitbucket-owner@acme.example", "email") in seeds
    assert ("https://bitbucket-pipelines.acme.example/build", "url") in seeds
    assert ("https://bitbucket.org/acme/pipeline-templates", "url") in seeds
    assert ("https://bitbucket.org/acme/infra-scripts", "url") in seeds
    assert ("https://ghcr.io/acme/bitbucket-runner", "url") in seeds
    assert ("https://registry.gitlab.com/acme/ci-scanner", "url") in seeds

    cloud_assets = _cloud_assets(db_path)
    assert ("aws_s3", "acme-bitbucket-pipelines-bucket") in cloud_assets
    assert ("bitbucket_pipeline", "deploy-prod") in cloud_assets

    artifact_meta = _artifact_meta(db_path)
    assert artifact_meta[bitbucket_path.resolve().as_posix()]["format"] == "bitbucket-pipelines"


def run_azure_pipelines_resource_refs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_azure_pipelines"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    azure_pipelines_path = artifact_root / "azure-pipelines.yml"
    azure_pipelines_path.write_text(
        dedent(
            """
            name: deploy
            trigger:
              - main
            resources:
              repositories:
                - repository: templates
                  type: github
                  name: acme/azure-pipeline-templates
                - repository: bitbucketTools
                  type: bitbucket
                  name: acme/azure-tools
                - repository: internalTools
                  type: git
                  url: https://dev.azure.com/acme/platform/_git/infra-tools
              containers:
                - container: build
                  image: ghcr.io/acme/azdo-build:latest
            jobs:
              - job: deploy
                container: mcr.microsoft.com/azure-cli:latest
                variables:
                  OWNER_EMAIL: azure-pipelines-owner@acme.example
                  STATUS_URL: https://azure-pipelines.acme.example/status
                  FIREBASE_URL: https://azpipeline-firebase.firebaseio.com
                  ARCHIVE_URI: gs://acme-azure-pipelines-gcs/reports/latest.json
                steps:
                  - script: echo deploy
            """
        ).strip(),
        encoding="utf-8",
    )

    queued, summary = _process_artifacts(db_path, artifact_root)

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.discovered_seeds >= 8

    seeds = _seed_pairs(db_path)
    for expected_url in {
        "https://azure-pipelines.acme.example/status",
        "https://bitbucket.org/acme/azure-tools",
        "https://dev.azure.com/acme/platform/_git/infra-tools",
        "https://ghcr.io/acme/azdo-build",
        "https://github.com/acme/azure-pipeline-templates",
        "https://mcr.microsoft.com/azure-cli",
    }:
        assert (expected_url, "url") in seeds
    assert ("azure-pipelines-owner@acme.example", "email") in seeds

    cloud_assets = _cloud_assets(db_path)
    assert ("azure_pipeline", "deploy") in cloud_assets
    assert ("firebase", "azpipeline-firebase") in cloud_assets
    assert ("gcs", "acme-azure-pipelines-gcs") in cloud_assets

    artifact_meta = _artifact_meta(db_path)
    assert artifact_meta[azure_pipelines_path.resolve().as_posix()]["format"] == "azure-pipelines"


def run_gitlab_ci_include_refs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_gitlab_ci"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    gitlab_ci_path = artifact_root / ".gitlab-ci.yml"
    gitlab_ci_path.write_text(
        dedent(
            """
            workflow:
              name: deploy
            stages: [build, deploy]
            include:
              - project: acme/ci-templates
                file: /templates/deploy.yml
                ref: v2
              - project: gitlab.example.com/security/shared-pipelines
                file: /security/scan.yml
              - remote: https://gitlab.com/acme/remote-pipelines/raw/main/deploy.yml
              - component: gitlab.com/acme/components/deploy@1.0.0
            default:
              image: registry.gitlab.com/acme/build-image:latest
              services:
                - name: registry.gitlab.com/acme/postgres:14
            deploy:
              stage: deploy
              variables:
                OWNER_EMAIL: gitlab-ci-owner@acme.example
                STATUS_URL: https://gitlab-ci.acme.example/deploy
                FIREBASE_URL: https://gitlabci-firebase.firebaseio.com
                ARCHIVE_URI: s3://acme-gitlab-ci-artifacts/reports/latest.json
              script:
                - echo deploy
              services:
                - registry.gitlab.com/acme/redis:7
            """
        ).strip(),
        encoding="utf-8",
    )

    queued, summary = _process_artifacts(db_path, artifact_root)

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.discovered_seeds >= 10

    seeds = _seed_pairs(db_path)
    for expected_url in {
        "https://gitlab-ci.acme.example/deploy",
        "https://gitlab.com/acme/ci-templates",
        "https://gitlab.example.com/security/shared-pipelines",
        "https://gitlab.com/acme/remote-pipelines/raw/main/deploy.yml",
        "https://gitlab.com/acme/components",
        "https://registry.gitlab.com/acme/build-image",
        "https://registry.gitlab.com/acme/postgres",
        "https://registry.gitlab.com/acme/redis",
    }:
        assert (expected_url, "url") in seeds
    assert ("gitlab-ci-owner@acme.example", "email") in seeds

    cloud_assets = _cloud_assets(db_path)
    assert ("aws_s3", "acme-gitlab-ci-artifacts") in cloud_assets
    assert ("firebase", "gitlabci-firebase") in cloud_assets
    assert ("gitlab_pipeline", "deploy") in cloud_assets

    artifact_meta = _artifact_meta(db_path)
    assert artifact_meta[gitlab_ci_path.resolve().as_posix()]["format"] == "gitlab-ci"
