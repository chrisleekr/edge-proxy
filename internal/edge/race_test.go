//go:build race

package edge

// raceEnabled is true under -race, where sync.Pool drops items at random by
// design, so pooled code may allocate.
const raceEnabled = true
