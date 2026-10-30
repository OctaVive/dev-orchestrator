// Package composefixtures embeds data for isolated M08 tests only.
package composefixtures

import "embed"

//go:embed *.yaml
var Files embed.FS
