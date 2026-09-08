//go:build e2e

package e2e

import (
	"net"
	"strconv"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func (f *Framework) SSHClientExec(user string, auth cryptossh.AuthMethod, command string) (string, error) {
	f.T.Helper()
	config := &cryptossh.ClientConfig{
		User:            user,
		Auth:            []cryptossh.AuthMethod{auth},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	client, err := cryptossh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.GatewayPort)), config)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	return string(output), err
}
