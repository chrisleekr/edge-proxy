//go:build race

package expr

// raceEnabled is true under -race, where sync.Pool drops items at random by
// design, so pooled code (regexp) may allocate.
const raceEnabled = true
