package testenv

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PlaywrightVersion matches @playwright/test in web/admin/package.json; the
// client and the server must be the same release.
const PlaywrightVersion = "1.64.1"

// PlaywrightImage is the browser server for PlaywrightVersion. It runs as
// amd64 so screenshots taken on an arm64 Mac render as on the CI runners.
const PlaywrightImage = "mcr.microsoft.com/playwright:v1.64.1-noble"

// PlaywrightServer starts a Playwright browser server in Docker and returns
// its WebSocket endpoint.
func PlaywrightServer(t testing.TB) string {
	t.Helper()
	if !strings.Contains(PlaywrightImage, ":v"+PlaywrightVersion+"-") {
		t.Fatalf("%s is not Playwright %s", PlaywrightImage, PlaywrightVersion)
	}
	// The server has no authentication and Docker publishes its port on
	// every host interface, so it listens on an unguessable path.
	path := "/" + rand.Text()
	ctx := context.Background() //nolint:usetesting // stopped in Cleanup, after t.Context is cancelled
	c, err := testcontainers.Run(ctx, PlaywrightImage,
		testcontainers.WithImagePlatform("linux/amd64"),
		testcontainers.WithExposedPorts("3000/tcp"),
		testcontainers.WithConfigModifier(func(cfg *container.Config) { cfg.User, cfg.WorkingDir = "pwuser", "/home/pwuser" }),
		// An init process reaps the browsers' children and stops on SIGTERM.
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) { hc.Init = new(true) }),
		testcontainers.WithCmd("/bin/sh", "-c", "npx -y playwright@"+PlaywrightVersion+" run-server --port 3000 --host 0.0.0.0 --path "+path),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("3000/tcp").WithStartupTimeout(5*time.Minute)),
	)
	if c != nil {
		t.Cleanup(func() { _ = c.Terminate(context.Background()) }) //nolint:usetesting // t.Context is already cancelled when Cleanup runs
	}
	if err != nil {
		t.Fatalf("start playwright server: %v", err)
	}
	host, err := hostOf(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.MappedPort(ctx, "3000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("ws://%s:%d%s", host, p.Num(), path)
}
