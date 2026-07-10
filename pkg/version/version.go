package version

import "fmt"

var (
	GitVersion = "dev"
	GitCommit  = "unknown"
	BuildDate  = "unknown"
)

type Info struct {
	GitVersion string `json:"gitVersion"`
	GitCommit  string `json:"gitCommit"`
	BuildDate  string `json:"buildDate"`
}

func Get() Info {
	return Info{
		GitVersion: GitVersion,
		GitCommit:  GitCommit,
		BuildDate:  BuildDate,
	}
}

func (i Info) String() string {
	return fmt.Sprintf("%s (%s, %s)", i.GitVersion, i.GitCommit, i.BuildDate)
}
