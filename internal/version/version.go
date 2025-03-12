package version

// Version information
var (
	// Version is the current version of Phoenix
	Version = "0.1.0"
	
	// GitCommit is the git commit that was compiled
	GitCommit = "development"
	
	// BuildDate is the date when the binary was built
	BuildDate = "unknown"
	
	// GoVersion is the version of Go used to compile
	GoVersion = "unknown"
)

// BuildInfo contains all build information
type BuildInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
}

// GetBuildInfo returns all build information
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: GoVersion,
	}
}