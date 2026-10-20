package buildinfo

import "runtime"

// Version and Commit are populated by the release build script.
var Version = "dev"
var Commit = "unknown"

// ID is shared by the embedded console and the API upgrade check.
func ID() string { return Version + "+" + Commit }

func String() string {
	return "DraFRP " + Version + " (" + Commit + "; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
