// metadata-upgrade is an explicit offline operator tool, never an API action.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"dev-orchestrator/internal/storage"
)

func main() {
	database := flag.String("database", "", "existing metadata database; stop all writers first")
	backup := flag.String("backup", "", "new snapshot file in an existing private directory")
	flag.Parse()
	if *database == "" || *backup == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, e := storage.UpgradeWithBackup(ctx, *database, *backup)
	if sum != "" {
		fmt.Println("backup_sha256=" + sum)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "metadata upgrade failed:", e)
		os.Exit(1)
	}
}
