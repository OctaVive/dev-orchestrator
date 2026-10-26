// Package migrations embeds immutable, numbered metadata schema migrations.
package migrations

import "embed"

//go:embed *.sql
var Files embed.FS
