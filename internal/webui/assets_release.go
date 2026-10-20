//go:build release

package webui

import (
	"embed"
	"io/fs"
)

// Release builds deliberately fail when the build pipeline has not copied a
// real Vite output into this directory.
//
//go:embed dist/* dist/assets/*
var releaseAssets embed.FS

func staticFS() fs.FS {
	f, err := fs.Sub(releaseAssets, "dist")
	if err != nil {
		panic(err)
	}
	return f
}
