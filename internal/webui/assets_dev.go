//go:build !release

package webui

import (
	"io/fs"
	"testing/fstest"
)

// devIndex keeps ordinary Go builds independent of the generated web/dist tree.
// Vite serves the real console during development.
const devIndex = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>DraFRP console development</title></head><body><p>DraFRP console is served by Vite in development mode.</p></body></html>`

func staticFS() fs.FS {
	return fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(devIndex), Mode: 0444}}
}
