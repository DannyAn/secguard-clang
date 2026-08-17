package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DannyAn/secguard-clang/internal/skills"
)

func runQueryCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	if len(remaining) == 0 {
		WriteErrorJSON("query requires a skill name argument")
		return 1
	}
	skillName := remaining[0]

	dbPath = resolveDBPath(dbExplicit, dbPath, ".")

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

	// 完整数据写到文件，stdout 只返回摘要 + 文件路径。
	// 避免大量 candidates 打印到 agent 上下文。
	candidatesFile := filepath.Join(filepath.Dir(dbPath), fmt.Sprintf("query-%s-%d.json", skillName, time.Now().Unix()))
	if werr := os.WriteFile(candidatesFile, result.Data, 0644); werr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write candidates file: %v\n", werr)
	}

	candidateCount := 0
	vulnType := skillName
	var parsed map[string]interface{}
	if json.Unmarshal(result.Data, &parsed) == nil {
		if vt, ok := parsed["vulnerability_type"].(string); ok {
			vulnType = vt
		}
		if cands, ok := parsed["candidates"].([]interface{}); ok {
			candidateCount = len(cands)
		}
	}

	summary, _ := json.MarshalIndent(map[string]interface{}{
		"skill_name":         skillName,
		"vulnerability_type": vulnType,
		"candidate_count":    candidateCount,
		"candidates_file":    candidatesFile,
	}, "", "  ")
	fmt.Fprintln(os.Stdout, string(summary))
	return 0
}
