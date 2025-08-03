{{/*
Expand the name of the chart.
*/}}
{{- define "qes-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "qes-platform.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "qes-platform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "qes-platform.labels" -}}
helm.sh/chart: {{ include "qes-platform.chart" . }}
{{ include "qes-platform.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "qes-platform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qes-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "qes-platform.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "qes-platform.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "qes-platform.image" -}}
{{- if .Values.global.imageRegistry }}
{{- printf "%s/%s:%s" .Values.global.imageRegistry .Values.api.image.repository .Values.api.image.tag }}
{{- else }}
{{- printf "%s:%s" .Values.api.image.repository .Values.api.image.tag }}
{{- end }}
{{- end }}

{{/*
PostgreSQL host
*/}}
{{- define "qes-platform.postgresql.host" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" (include "qes-platform.fullname" .) }}
{{- else }}
{{- .Values.postgresql.external.host }}
{{- end }}
{{- end }}

{{/*
PostgreSQL port
*/}}
{{- define "qes-platform.postgresql.port" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "5432" }}
{{- else }}
{{- .Values.postgresql.external.port | toString }}
{{- end }}
{{- end }}

{{/*
PostgreSQL database
*/}}
{{- define "qes-platform.postgresql.database" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.postgresql.external.database }}
{{- end }}
{{- end }}

{{/*
Redis host
*/}}
{{- define "qes-platform.redis.host" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" (include "qes-platform.fullname" .) }}
{{- else }}
{{- .Values.redis.external.host }}
{{- end }}
{{- end }}

{{/*
Redis port
*/}}
{{- define "qes-platform.redis.port" -}}
{{- if .Values.redis.enabled }}
{{- printf "6379" }}
{{- else }}
{{- .Values.redis.external.port | toString }}
{{- end }}
{{- end }}

{{/*
Vault host
*/}}
{{- define "qes-platform.vault.host" -}}
{{- printf "%s-vault" (include "qes-platform.fullname" .) }}
{{- end }}

{{/*
MinIO host
*/}}
{{- define "qes-platform.minio.host" -}}
{{- if .Values.minio.enabled }}
{{- printf "%s-minio" (include "qes-platform.fullname" .) }}
{{- else }}
{{- .Values.minio.external.endpoint }}
{{- end }}
{{- end }}

{{/*
Create secret name for QES Platform
*/}}
{{- define "qes-platform.secretName" -}}
{{- printf "%s-secrets" (include "qes-platform.fullname" .) }}
{{- end }}

{{/*
Create ConfigMap name for SoftHSM
*/}}
{{- define "qes-platform.softhsm.configMapName" -}}
{{- printf "%s-softhsm-config" (include "qes-platform.fullname" .) }}
{{- end }}

{{/*
Generate certificates for Vault
*/}}
{{- define "qes-platform.vault.gen-certs" -}}
{{- $ca := genCA "vault-ca" 365 }}
{{- $cert := genSignedCert "vault" nil (list "vault" "vault.vault" "vault.vault.svc" "vault.vault.svc.cluster.local" "localhost") 365 $ca }}
tls.crt: {{ $cert.Cert | b64enc }}
tls.key: {{ $cert.Key | b64enc }}
ca.crt: {{ $ca.Cert | b64enc }}
{{- end }}

{{/*
Common annotations for all resources
*/}}
{{- define "qes-platform.annotations" -}}
meta.helm.sh/release-name: {{ .Release.Name }}
meta.helm.sh/release-namespace: {{ .Release.Namespace }}
{{- if .Values.commonAnnotations }}
{{- toYaml .Values.commonAnnotations }}
{{- end }}
{{- end }}

{{/*
Pod anti-affinity rules
*/}}
{{- define "qes-platform.podAntiAffinity" -}}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
  - weight: 100
    podAffinityTerm:
      labelSelector:
        matchExpressions:
        - key: app.kubernetes.io/name
          operator: In
          values:
          - {{ include "qes-platform.name" . }}
        - key: app.kubernetes.io/component
          operator: In
          values:
          - api
      topologyKey: kubernetes.io/hostname
{{- end }}

{{/*
Resource limits and requests
*/}}
{{- define "qes-platform.resources" -}}
{{- if .resources }}
resources:
  {{- if .resources.limits }}
  limits:
    {{- if .resources.limits.cpu }}
    cpu: {{ .resources.limits.cpu }}
    {{- end }}
    {{- if .resources.limits.memory }}
    memory: {{ .resources.limits.memory }}
    {{- end }}
  {{- end }}
  {{- if .resources.requests }}
  requests:
    {{- if .resources.requests.cpu }}
    cpu: {{ .resources.requests.cpu }}
    {{- end }}
    {{- if .resources.requests.memory }}
    memory: {{ .resources.requests.memory }}
    {{- end }}
  {{- end }}
{{- end }}
{{- end }}