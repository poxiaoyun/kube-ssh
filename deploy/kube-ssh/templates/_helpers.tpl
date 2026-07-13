{{- define "kube-ssh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kube-ssh.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "kube-ssh.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kube-ssh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kube-ssh.labels" -}}
helm.sh/chart: {{ include "kube-ssh.chart" . }}
app.kubernetes.io/name: {{ include "kube-ssh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.kubeSsh.commonLabels }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end -}}

{{- define "kube-ssh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-ssh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "kube-ssh.serviceAccountName" -}}
{{- if .Values.kubeSsh.serviceAccount.create -}}
{{- default (include "kube-ssh.fullname" .) .Values.kubeSsh.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.kubeSsh.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "kube-ssh.image" -}}
{{- $registry := default .Values.global.imageRegistry .Values.kubeSsh.image.registry -}}
{{- $repository := .Values.kubeSsh.image.repository -}}
{{- if .Values.global.imageRepository -}}
{{- $repository = printf "%s/%s" .Values.global.imageRepository (base $repository) -}}
{{- end -}}
{{- $tag := default .Chart.AppVersion .Values.kubeSsh.image.tag -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "kube-ssh.imagePullSecrets" -}}
{{- $secrets := concat (.Values.global.imagePullSecrets | default list) (.Values.kubeSsh.image.pullSecrets | default list) -}}
{{- if $secrets }}
imagePullSecrets:
{{- range $secrets }}
  - name: {{ . | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "kube-ssh.hostKeySecretName" -}}
{{- if .Values.kubeSsh.hostKey.existingSecret -}}
{{- .Values.kubeSsh.hostKey.existingSecret -}}
{{- else -}}
{{- printf "%s-host-key" (include "kube-ssh.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "kube-ssh.webhookEnv" -}}
{{- $prefix := .prefix -}}
{{- $webhook := .webhook -}}
{{- with $webhook.server }}
- name: {{ printf "%s_WEBHOOK_SERVER" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- with $webhook.proxyURL }}
- name: {{ printf "%s_WEBHOOK_PROXY_URL" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- with $webhook.token }}
- name: {{ printf "%s_WEBHOOK_TOKEN" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- with $webhook.username }}
- name: {{ printf "%s_WEBHOOK_USERNAME" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- with $webhook.password }}
- name: {{ printf "%s_WEBHOOK_PASSWORD" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- with $webhook.caFile }}
- name: {{ printf "%s_WEBHOOK_CA_FILE" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- with $webhook.certFile }}
- name: {{ printf "%s_WEBHOOK_CERT_FILE" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- with $webhook.keyFile }}
- name: {{ printf "%s_WEBHOOK_KEY_FILE" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- if $webhook.insecureSkipTLSVerify }}
- name: {{ printf "%s_WEBHOOK_INSECURE_SKIP_TLS_VERIFY" (upper $prefix) }}
  value: "true"
{{- end }}
{{- with $webhook.timeout }}
- name: {{ printf "%s_WEBHOOK_TIMEOUT" (upper $prefix) }}
  value: {{ . | quote }}
{{- end }}
{{- end -}}
