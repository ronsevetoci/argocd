{{- define "demo-api.name" -}}
demo-api
{{- end -}}

{{- define "demo-api.fullname" -}}
{{ include "demo-api.name" . }}
{{- end -}}

{{- define "demo-api.labels" -}}
app.kubernetes.io/name: {{ include "demo-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "demo-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "demo-api.name" . }}
{{- end -}}
