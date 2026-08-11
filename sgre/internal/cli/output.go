package cli

import (
	"encoding/json"
	"fmt"
	"os"
)

func WriteJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("cli: write json: %w", err)
	}
	_, err = fmt.Fprintln(os.Stdout, string(data))
	return err
}

func WriteErrorJSON(msg string) {
	data, _ := json.Marshal(map[string]string{"error": msg})
	fmt.Fprintln(os.Stdout, string(data))
}
