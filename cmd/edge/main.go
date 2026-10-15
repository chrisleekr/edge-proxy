// Command edge is the edge proxy. Configuration is read from the
// environment.
package main

import (
	"context"
	"os"

	"github.com/chrisleekr/edge-proxy/internal/edge"
)

func main() {
	os.Exit(edge.Main(context.Background(), os.Getenv, os.Stdout))
}
