{{- define "hsmgate.name" -}}{{ default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "hsmgate.fullname" -}}
{{- if .Values.fullnameOverride }}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "hsmgate.name" .) .Release.Name }}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}{{ printf "%s-%s" .Release.Name (include "hsmgate.name" .) | trunc 63 | trimSuffix "-" }}{{- end }}
{{- end -}}
{{- define "hsmgate.labels" -}}
app.kubernetes.io/name: {{ include "hsmgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}
{{- define "hsmgate.selector" -}}
app.kubernetes.io/name: {{ include "hsmgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "hsmgate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "hsmgate.fullname" .) .Values.serviceAccount.name }}{{ else }}{{ default "default" .Values.serviceAccount.name }}{{ end }}
{{- end -}}
{{- define "hsmgate.image" -}}
{{- if .Values.image.digest }}{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}{{ printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}{{ end }}
{{- end -}}
{{- define "hsmgate.softSecret" -}}{{ default (printf "%s-soft" (include "hsmgate.fullname" .)) .Values.softToken.existingSecret }}{{- end -}}
{{- define "hsmgate.tlsSecret" -}}{{- if not (or .Values.tls.existingSecret .Values.tls.generate.enabled) }}{{ fail "tls: set existingSecret or leave generate.enabled on" }}{{ end }}{{ default (printf "%s-tls" (include "hsmgate.fullname" .)) .Values.tls.existingSecret }}{{- end -}}
