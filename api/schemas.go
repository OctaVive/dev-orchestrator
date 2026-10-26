// Package api embeds versioned protocol schemas. They are not user supplied.
package api

import "embed"

// Schemas contains only local trusted schema resources. Validators must never
// fetch schemas from a request-controlled URL.
//
//go:embed *.schema.json
var Schemas embed.FS
