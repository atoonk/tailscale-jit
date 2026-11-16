{{/* Chart name, truncated to fit a label. */}}
{{- define "jitd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Release-scoped name for the chart's objects. */}}
{{- define "jitd.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "jitd.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "jitd.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "jitd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jitd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "jitd.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "jitd.selectorLabels" . }}
app.kubernetes.io/version: {{ include "jitd.version" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "jitd.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "jitd.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Release tag to run. */}}
{{- define "jitd.version" -}}
{{- default .Chart.AppVersion .Values.release.version }}
{{- end }}

{{/* Architecture of the binary, checked. */}}
{{- define "jitd.arch" -}}
{{- $arch := .Values.release.arch }}
{{- if not (has $arch (list "amd64" "arm64")) }}
{{- fail (printf "release.arch must be amd64 or arm64, not %q" $arch) }}
{{- end }}
{{- $arch }}
{{- end }}

{{/* Download URL of the binary. */}}
{{- define "jitd.url" -}}
{{- if .Values.release.url }}
{{- .Values.release.url }}
{{- else }}
{{- printf "https://github.com/%s/releases/download/%s/jitd-linux-%s" .Values.release.repository (include "jitd.version" .) (include "jitd.arch" .) }}
{{- end }}
{{- end }}

{{/* Expected sha256 of the binary. */}}
{{- define "jitd.sha256" -}}
{{- $sum := index .Values.release.sha256 (include "jitd.arch" .) | default "" }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sum) }}
{{- fail (printf "release.sha256.%s must be the 64-character sha256 of the binary, from the release's SHA256SUMS" (include "jitd.arch" .)) }}
{{- end }}
{{- $sum }}
{{- end }}

{{/* Name of the Secret with the credentials, or "" for none. */}}
{{- define "jitd.secretName" -}}
{{- if .Values.credentials.existingSecret }}
{{- .Values.credentials.existingSecret }}
{{- else if .Values.credentials.values }}
{{- include "jitd.fullname" . }}
{{- end }}
{{- end }}

{{/* Name of the data PersistentVolumeClaim. */}}
{{- define "jitd.claimName" -}}
{{- default (printf "%s-data" (include "jitd.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}
