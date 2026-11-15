{{- define "kubechaos-operator.name" -}}kubechaos-operator{{- end -}}

{{- define "kubechaos-operator.labels" -}}
app.kubernetes.io/name: kubechaos-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/component: operator
app.kubernetes.io/part-of: kubechaos
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kubechaos-operator.selectorLabels" -}}
app.kubernetes.io/name: kubechaos-operator
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kubechaos-operator.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}

{{/* Fail the install (closed) on an invalid cluster identity. */}}
{{- define "kubechaos-operator.validateIdentity" -}}
{{- $id := .Values.clusterIdentity -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$" ($id.clusterID | toString)) -}}
{{- fail "clusterIdentity.clusterID must be a DNS-1123 label (e.g. dev-kind-01)" -}}
{{- end -}}
{{- if not (has ($id.environment | toString) (list "development" "staging" "production")) -}}
{{- fail "clusterIdentity.environment must be one of development, staging, production" -}}
{{- end -}}
{{- if ne .Release.Namespace "kubechaos-system" -}}
{{- fail "install into namespace kubechaos-system (created from deploy/k8s/namespace.yaml with Pod Security labels)" -}}
{{- end -}}
{{- end -}}
