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

{{- define "kube-ssh.webhookArgs" -}}
{{- $prefix := .prefix -}}
{{- $webhook := .webhook -}}
{{- with $webhook.server }}
- {{ printf "--%s-webhook-server=%s" $prefix . | quote }}
{{- end }}
{{- with $webhook.proxyURL }}
- {{ printf "--%s-webhook-proxy-url=%s" $prefix . | quote }}
{{- end }}
{{- with $webhook.token }}
- {{ printf "--%s-webhook-token=%s" $prefix . | quote }}
{{- end }}
{{- with $webhook.username }}
- {{ printf "--%s-webhook-username=%s" $prefix . | quote }}
{{- end }}
{{- with $webhook.password }}
- {{ printf "--%s-webhook-password=%s" $prefix . | quote }}
{{- end }}
{{- with $webhook.caFile }}
- {{ printf "--%s-webhook-ca-file=%s" $prefix . | quote }}
{{- end }}
{{- with $webhook.certFile }}
- {{ printf "--%s-webhook-cert-file=%s" $prefix . | quote }}
{{- end }}
{{- with $webhook.keyFile }}
- {{ printf "--%s-webhook-key-file=%s" $prefix . | quote }}
{{- end }}
{{- if $webhook.insecureSkipTLSVerify }}
- {{ printf "--%s-webhook-insecure-skip-tls-verify=true" $prefix | quote }}
{{- end }}
{{- with $webhook.timeout }}
- {{ printf "--%s-webhook-timeout=%s" $prefix . | quote }}
{{- end }}
{{- end -}}
