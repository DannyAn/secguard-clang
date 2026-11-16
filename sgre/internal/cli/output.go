package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// cliStdout is the single sink every machine-readable CLI envelope is written
// to. It is a var (not a hardcoded os.Stdout) so a parent command can capture a
// sub-command's envelope — `secguard finalize` replays staged verdicts by
// re-entering the report command and must fold each sub-result into its own
// envelope instead of leaking N JSON blobs onto the real stdout. The test
// helper captureOutput swaps it in lockstep with os.Stdout so captured output
// still reflects every envelope a command prints.
var cliStdout io.Writer = os.Stdout

func WriteJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("cli: write json: %w", err)
	}
	_, err = fmt.Fprintln(cliStdout, string(data))
	return err
}

func WriteErrorJSON(msg string) {
	data, _ := json.Marshal(map[string]string{"error": msg})
	fmt.Fprintln(cliStdout, string(data))
}
