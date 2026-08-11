package planner

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/DannyAn/secguard-clang/internal/db"
)

var criticalAPIs = map[string]bool{
	"system": true, "popen": true,
	"CreateProcessA": true, "CreateProcessW": true,
	"CreateProcessAsA": true, "CreateProcessAsW": true,
	"ShellExecuteA": true, "ShellExecuteW": true,
	"ShellExecuteEx": true, "ShellExecuteExA": true, "ShellExecuteExW": true,
	"execl": true, "execlp": true, "execle": true,
	"execv": true, "execvp": true, "execve": true,
}

var highAPIs = map[string]bool{
	"strcpy": true, "strcat": true, "sprintf": true,
	"gets": true, "memcpy": true,
}

var mediumAPIs = map[string]bool{
	"strncpy": true, "strncat": true, "snprintf": true,
	"fread": true, "scanf": true, "sscanf": true, "fscanf": true,
}

func initHighImpactAPIs() map[string]bool {
	result := make(map[string]bool)
	for k := range criticalAPIs {
		result[k] = true
	}
	for k := range highAPIs {
		result[k] = true
	}
	return result
}

func severityValue(apiName string) float64 {
	if criticalAPIs[apiName] {
		return 100
	}
	if highAPIs[apiName] {
		return 80
	}
	if mediumAPIs[apiName] {
		return 60
	}
	if apiName != "" {
		return 40
	}
	return 20
}

func confidenceValue(suspicionLevel string) float64 {
	switch suspicionLevel {
	case "confirmed":
		return 1.0
	case "suspected":
		return 0.7
	case "possible":
		return 0.5
	default:
		return 0.5
	}
}

func computeQualityScore(c Candidate, apiName string) float64 {
	severity := severityValue(apiName)
	confidence := confidenceValue(c.SuspicionLevel)
	if c.GuardStrength == "weak" {
		confidence *= 0.8
	}
	highImpact := initHighImpactAPIs()
	impactBonus := 0.0
	if highImpact[apiName] {
		impactBonus = 20
	}
	score := severity*0.60 + confidence*0.25*100 + impactBonus*0.15
	return score
}

func RankCandidates(ctx context.Context, candidates []Candidate, store db.Store) []Candidate {
	if len(candidates) == 0 {
		return candidates
	}

	for i := range candidates {
		apiName := ""
		if store != nil && candidates[i].DerefEventID > 0 {
			event, err := store.GetEventByID(ctx, candidates[i].DerefEventID)
			if err == nil && event != nil {
				var props struct {
					Function   string `json:"function"`
					Variable   string `json:"variable"`
					Expression string `json:"expression"`
				}
				json.Unmarshal([]byte(event.Properties), &props)
				apiName = props.Function
				if apiName == "" {
					apiName = props.Variable
				}
			}
		}
		candidates[i].QualityScore = computeQualityScore(candidates[i], apiName)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].QualityScore != candidates[j].QualityScore {
			return candidates[i].QualityScore > candidates[j].QualityScore
		}
		if candidates[i].FileID != candidates[j].FileID {
			return candidates[i].FileID < candidates[j].FileID
		}
		return candidates[i].Line < candidates[j].Line
	})

	return candidates
}
