// Package testenv starts real dependencies for tests with testcontainers.
// It is test tooling: cmd/edge must never import it (scripts/ci/test.sh).
package testenv

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ValkeyImage matches compose.yaml.
const ValkeyImage = "valkey/valkey:9.1.2-alpine"

var (
	standaloneOnce sync.Once
	standaloneAddr string
	standaloneErr  error

	clusterOnce sync.Once
	cluster     *Cluster
	clusterErr  error
)

// Valkey returns host:port of a standalone Valkey shared by the test
// process. Tests isolate themselves by key, never by flushing.
func Valkey(t testing.TB) string {
	t.Helper()
	standaloneOnce.Do(func() {
		ctx := context.Background() //nolint:usetesting // the container is process-wide and outlives this test
		c, err := testcontainers.Run(ctx, ValkeyImage,
			testcontainers.WithExposedPorts("6379/tcp"),
			testcontainers.WithCmd("valkey-server", "--save", "", "--appendonly", "no"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp").WithStartupTimeout(time.Minute)),
		)
		if err != nil {
			standaloneErr = err
			return
		}
		host, err := hostOf(ctx, c)
		if err != nil {
			standaloneErr = err
			return
		}
		p, err := c.MappedPort(ctx, "6379/tcp")
		if err != nil {
			standaloneErr = err
			return
		}
		standaloneAddr = net.JoinHostPort(host, strconv.Itoa(int(p.Num())))
	})
	if standaloneErr != nil {
		t.Fatalf("start valkey: %v", standaloneErr)
	}
	return standaloneAddr
}

// Cluster is a three-primary Valkey Cluster in one container. Each node
// listens on the same port inside and outside the container and announces
// the Docker host, so clients follow CLUSTER SLOTS without NAT tricks.
type Cluster struct {
	Addrs []string
	c     *testcontainers.DockerContainer
	ports []int
	host  string
}

// ValkeyCluster returns the process-wide cluster, starting it on first use.
func ValkeyCluster(t testing.TB) *Cluster {
	t.Helper()
	clusterOnce.Do(func() {
		// Free ports are picked before Docker binds them, so another
		// process can take one in between; pick again then.
		for range 3 {
			cluster, clusterErr = startCluster(context.Background()) //nolint:usetesting // the container is process-wide and outlives this test
			if clusterErr == nil || !strings.Contains(clusterErr.Error(), "address already in use") {
				return
			}
		}
	})
	if clusterErr != nil {
		t.Fatalf("start valkey cluster: %v", clusterErr)
	}
	return cluster
}

func startCluster(ctx context.Context) (*Cluster, error) {
	ports, err := freePorts(3)
	if err != nil {
		return nil, err
	}
	var exposed []string
	bindings := network.PortMap{}
	for _, p := range ports {
		exposed = append(exposed, fmt.Sprintf("%d/tcp", p))
		bindings[network.MustParsePort(fmt.Sprintf("%d/tcp", p))] = []network.PortBinding{{HostPort: strconv.Itoa(p)}}
	}
	c, err := testcontainers.Run(ctx, ValkeyImage,
		testcontainers.WithExposedPorts(exposed...),
		testcontainers.WithEntrypoint("sleep", "infinity"),
		testcontainers.WithHostConfigModifier(func(h *container.HostConfig) { h.PortBindings = bindings }),
	)
	if err != nil {
		return nil, err
	}
	host, err := hostOf(ctx, c)
	if err != nil {
		return nil, err
	}
	cl := &Cluster{c: c, ports: ports, host: host}
	var script strings.Builder
	for i, p := range ports {
		script.WriteString(cl.serverCmd(i) + "\n")
		cl.Addrs = append(cl.Addrs, net.JoinHostPort(host, strconv.Itoa(p)))
	}
	for _, p := range ports {
		fmt.Fprintf(&script, "until valkey-cli -p %d ping; do sleep 0.1; done\n", p)
	}
	fmt.Fprintf(&script, "valkey-cli --cluster create 127.0.0.1:%d 127.0.0.1:%d 127.0.0.1:%d --cluster-yes\n", ports[0], ports[1], ports[2])
	fmt.Fprintf(&script, "until valkey-cli -p %d cluster info | grep -q cluster_state:ok; do sleep 0.1; done\n", ports[0])
	if err := cl.exec(ctx, script.String()); err != nil {
		return nil, err
	}
	return cl, nil
}

// Stop shuts one node down, simulating a failed shard. Its slots stay
// unserved; Start brings it back with its data gone.
func (cl *Cluster) Stop(t testing.TB, node int) {
	t.Helper()
	if err := cl.exec(t.Context(), fmt.Sprintf("valkey-cli -p %d shutdown nosave || true", cl.ports[node])); err != nil {
		t.Fatal(err)
	}
}

// Start restarts a stopped node from its saved cluster config.
func (cl *Cluster) Start(t testing.TB, node int) {
	t.Helper()
	if err := cl.exec(t.Context(), cl.serverCmd(node)+fmt.Sprintf(
		" && until valkey-cli -p %d cluster info | grep -q cluster_state:ok; do sleep 0.1; done", cl.ports[node])); err != nil {
		t.Fatal(err)
	}
}

// serverCmd starts one node. The cluster bus port is set explicitly because
// the client port may be above 55535, where port+10000 does not exist.
func (cl *Cluster) serverCmd(node int) string {
	p := cl.ports[node]
	return fmt.Sprintf("valkey-server --port %d --cluster-port %d --cluster-enabled yes --cluster-config-file nodes-%d.conf --cluster-node-timeout 2000 --cluster-require-full-coverage no "+
		"--cluster-announce-hostname %s --cluster-preferred-endpoint-type hostname --save '' --appendonly no --daemonize yes", p, 16379+node, p, cl.host)
}

func (cl *Cluster) exec(ctx context.Context, script string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	code, out, err := cl.c.Exec(ctx, []string{"sh", "-c", script})
	if err != nil {
		return err
	}
	if code != 0 {
		b, _ := io.ReadAll(out)
		return fmt.Errorf("exit %d: %s", code, b)
	}
	return nil
}

// hostOf is the address tests dial. "localhost" may resolve to ::1 first,
// where Docker Desktop does not always publish.
func hostOf(ctx context.Context, c *testcontainers.DockerContainer) (string, error) {
	h, err := c.Host(ctx)
	if h == "localhost" {
		h = "127.0.0.1"
	}
	return h, err
}

func freePorts(n int) ([]int, error) {
	var out []int
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		out = append(out, l.Addr().(*net.TCPAddr).Port)
		defer func() { _ = l.Close() }() // held open so the next pick differs
	}
	return out, nil
}
