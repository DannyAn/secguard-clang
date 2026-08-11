package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/DannyAn/secguard-clang/internal/skills"
)

func runQueryCmd(ctx context.Context, args []string) int {
	dbPath, remaining := parseDBFlag(args)
	if len(remaining) == 0 {
		WriteErrorJSON("query requires a skill name argument")
		return 1
	}
	skillName := remaining[0]

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	logger := defaultLogger()
	reg := skills.DefaultRegistry(store, logger)

	skill, err := reg.Get(skillName)
	if err != nil {
		WriteErrorJSON(err.Error())
		return 1
	}

	result, err := skill.Query(ctx)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("query failed: %v", err))
		return 1
	}

	fmt.Fprintln(os.Stdout, string(result.Data))
	return 0
}
