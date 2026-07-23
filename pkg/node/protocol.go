package node

const (
	APIVersion = "v1"

	DefaultStreamPort  = 10443
	DefaultMetricsPort = 18080

	DefaultClientName = "kube-ssh-gateway"
)

const (
	QueryCommand  = "command"
	QueryArgument = "arg"
	QueryStdin    = "stdin"
	QueryStdout   = "stdout"
	QueryStderr   = "stderr"
	QueryTTY      = "tty"
	QueryPort     = "port"
)
