// Command admin is the admin service. Configuration is read from the
// environment.
//
//	admin [serve]                      run the API
//	admin migrate                      apply migrations as the owner role
//	admin create-user <name> <role>... add a local user; password on stdin
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/chrisleekr/edge-proxy/internal/admin"
	ui "github.com/chrisleekr/edge-proxy/web/admin"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(admin.Main(ctx, ui.FS(), os.Args[1:], os.Getenv, os.Stdin, os.Stdout))
}
