//go:build e2e

package e2e

import (
	"strconv"
	"strings"
	"time"
)

func (f *Framework) HelperProcessCount(user string) int {
	f.T.Helper()
	result := f.SSH(user, helperProcessCountCommand())
	if result.Code != 0 {
		f.T.Fatalf("count helper processes failed:\n%s", result.Dump())
	}
	count, err := strconv.Atoi(strings.TrimSpace(result.Stdout))
	if err != nil {
		f.T.Fatalf("parse helper process count from %q: %v\n%s", result.Stdout, err, result.Dump())
	}
	return count
}

func (f *Framework) HelperProcessSnapshot(user string) string {
	f.T.Helper()
	result := f.SSH(user, "for f in /proc/[0-9]*/cmdline; do cmd=$(tr '\\0' ' ' < \"$f\" 2>/dev/null); [ -n \"$cmd\" ] && echo \"$f $cmd\"; done")
	if result.Code != 0 {
		return result.Dump()
	}
	return result.Stdout
}

func (f *Framework) WaitHelperProcessCount(user string, want int, timeout time.Duration) {
	f.T.Helper()
	deadline := time.Now().
		Add(timeout)
	var got int
	for time.Now().
		Before(deadline) {
		got = f.HelperProcessCount(user)
		if got == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	f.T.Fatalf("helper process count = %d, want %d\nprocesses:\n%s", got, want, f.HelperProcessSnapshot(user))
}

func helperProcessCountCommand() string {
	return "needle=kube-ssh; needle=\"${needle}-helper\"; count=0; for f in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < \"$f\" 2>/dev/null | grep -q \"$needle\" && count=$((count+1)); done; echo \"$count\""
}
