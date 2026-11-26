package edge

import "testing"

// Every request's path is normalized, so a clean path, long or ending in
// "/", is returned as it came without an allocation.
func TestMatchPathCleanAllocatesNothing(t *testing.T) {
	for _, target := range []string{
		"/api/v2/customers/12345/orders/67890/line-items/latest/state", // 60 bytes
		"/api/v2/customers/12345/orders/",
	} {
		t.Run(target, func(t *testing.T) {
			r := rawTarget(t, target)
			if p, err := matchPath(r); p != target || err != nil {
				t.Fatalf("matchPath = %q, %v", p, err)
			}
			if n := testing.AllocsPerRun(100, func() { _, _ = matchPath(r) }); n != 0 {
				t.Fatalf("%v allocations per path", n)
			}
		})
	}
}
