{{- define "forge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "forge.fullname" -}}
{{- if .Values.fullnameOverride -}}{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}{{- else -}}{{- $name := default .Chart.Name .Values.nameOverride -}}{{- if contains $name .Release.Name -}}{{- .Release.Name | trunc 63 | trimSuffix "-" -}}{{- else -}}{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}{{- end -}}{{- end -}}
{{- end -}}
{{- define "forge.chart" -}}{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}{{- end -}}
{{- define "forge.labels" -}}
helm.sh/chart: {{ include "forge.chart" . }}
app.kubernetes.io/name: {{ include "forge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "forge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "forge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "forge.secretName" -}}
{{- default (include "forge.fullname" .) .Values.secrets.existingSecretName -}}
{{- end -}}
{{- define "forge.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
seccompProfile:
  type: RuntimeDefault
{{- end -}}
{{- define "forge.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end -}}
{{- define "forge.productionEnv" -}}
- name: FORGE_DEPLOYMENT_PROFILE
  value: production
- name: FORGE_ENV
  value: production
- name: FORGE_DATA_DIR
  value: /data
- name: FORGE_SAFE_MODE
  value: "1"
- name: FORGE_REQUIRE_SCOPE_MANIFEST
  value: "1"
- name: FORGE_NO_TOR
  value: "1"
- name: FORGE_WEB_ENABLED
  value: "1"
- name: FORGE_WEB_HOST
  value: 0.0.0.0
- name: FORGE_WEB_PORT
  value: "8080"
- name: FORGE_WEB_AUTH
  value: jwt
- name: FORGE_WEB_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "forge.secretName" . }}
      key: web-secret-key
- name: FORGE_WEB_BOOTSTRAP_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "forge.secretName" . }}
      key: web-bootstrap-token
- name: FORGE_ENGAGEMENT_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "forge.secretName" . }}
      key: engagement-key
- name: FORGE_SECURITY_HEADERS_DISABLE
  value: "0"
- name: FORGE_SECURITY_HSTS_SECONDS
  value: {{ .Values.securityHstsSeconds | quote }}
- name: FORGE_PUBLIC_BASE_URL
  value: {{ required "publicBaseUrl is required for production Helm deployments" .Values.publicBaseUrl | quote }}
- name: FORGE_TLS_TERMINATED_BY
  value: {{ .Values.tlsTerminatedBy | quote }}
- name: FORGE_DISTRIBUTED_ENABLED
  value: "1"
- name: FORGE_REDIS_URL
  value: {{ .Values.redis.url | quote }}
- name: FORGE_STATE_DB_URL
  value: "postgresql+asyncpg://{{ .Values.postgres.user }}:$(FORGE_POSTGRES_PASSWORD)@{{ .Values.postgres.host }}:{{ .Values.postgres.port }}/{{ .Values.postgres.database }}"
- name: FORGE_AUDIT_DB_URL
  value: "postgresql+asyncpg://{{ .Values.postgres.user }}:$(FORGE_POSTGRES_PASSWORD)@{{ .Values.postgres.host }}:{{ .Values.postgres.port }}/{{ .Values.postgres.database }}"
- name: FORGE_POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "forge.secretName" . }}
      key: postgres-password
- name: FORGE_AUDIT_LOG_PATH
  value: /data/audit/audit.jsonl
- name: FORGE_AUDIT_BUNDLE_REMOTE_URI
  value: file:///remote-audit
- name: FORGE_AUDIT_BUNDLE_REMOTE_SCOPE
  valueFrom:
    secretKeyRef:
      name: {{ include "forge.secretName" . }}
      key: audit-bundle-remote-scope
- name: FORGE_PLUGIN_DIR
  value: /plugins
{{- range $name, $value := .Values.env }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
{{- end -}}
