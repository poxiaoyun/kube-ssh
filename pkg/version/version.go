// Package version exposes linker-supplied process build information.
package version

import "fmt"

var (
	gitVersion = "dev"
	gitCommit  = "unknown"
	buildDate  = "unknown"
)

type Info struct {
	GitVersion string
	GitCommit  string
	BuildDate  string
}

func Get() Info {
	return Info{
		GitVersion: gitVersion,
		GitCommit:  gitCommit,
		BuildDate:  buildDate,
	}
}

func (i Info) String() string {
	return fmt.Sprintf("%s (%s, %s)", i.GitVersion, i.GitCommit, i.BuildDate)
}
