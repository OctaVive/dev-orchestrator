// Package dockerfilefixtures embeds data for isolated M08 tests only.
package dockerfilefixtures

import "embed"

//go:embed *.dockerfile
var Files embed.FS
