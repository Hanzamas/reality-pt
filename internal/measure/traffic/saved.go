package traffic

import (
	"encoding/json"
	"fmt"
	"os"
)

// SavedTrace is the start of one real connection, kept for later comparison.
// It holds sizes and directions only: no content, no addresses.
type SavedTrace struct {
	// Site is the public host the connection went to.
	Site string `json:"site"`
	// Steps are the first application data records after the handshake, as
	// pairs of direction (1 for client to server) and record length.
	Steps [][2]int `json:"steps"`
}

// SavedFile is the on-disk form of a set of traces.
type SavedFile struct {
	// Note says how the traces were made.
	Note   string       `json:"note"`
	Traces []SavedTrace `json:"traces"`
}

// NewSavedTrace keeps the first n steps.
func NewSavedTrace(site string, steps []Step, n int) SavedTrace {
	saved := SavedTrace{Site: site}
	for _, s := range steps[:min(n, len(steps))] {
		up := 0
		if s.Up {
			up = 1
		}
		saved.Steps = append(saved.Steps, [2]int{up, s.Len})
	}
	return saved
}

// AsSteps converts the trace back to steps.
func (s SavedTrace) AsSteps() []Step {
	steps := make([]Step, len(s.Steps))
	for i, p := range s.Steps {
		steps[i] = Step{Up: p[0] == 1, Len: p[1]}
	}
	return steps
}

// WriteSaved writes traces to path as JSON.
func WriteSaved(path string, f SavedFile) error {
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ReadSaved reads traces written by WriteSaved.
func ReadSaved(path string) (SavedFile, error) {
	var f SavedFile
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}
